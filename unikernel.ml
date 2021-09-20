open Lwt.Infix

let argument_error = 64

module Main (R : Mirage_random.S) (S : Mirage_stack.V4V6) (Http_client: Cohttp_lwt.S.Client) (Http: Cohttp_mirage.Server.S) (C: Mirage_clock.PCLOCK) (Time: Mirage_time.S) = struct

  let serve cb =
    let callback _ request body = cb request body
    and conn_closed _ = ()
    in
    Http.make ~conn_closed ~callback ()

  module TLS = Tls_mirage.Make(S.TCP)

  module HTTP_Server = struct
    let dispatch request _body =
      let p = Uri.path (Cohttp.Request.uri request) in
      let path = if String.equal p "/" then "index.html" else p in
      Logs.info (fun f -> f "requested %s" path);
      let reply = "hello at " ^ path in
      let mime_type = "text/plain" in
      let headers = [
        "content-type", mime_type ;
      ] in
      let headers = Cohttp.Header.of_list headers in
      Http.respond ~headers ~status:`OK ~body:(`String reply) ()

    let redirect request _body =
      let uri = Cohttp.Request.uri request in
      let new_uri = Uri.with_scheme uri (Some "https") in
      Logs.info (fun f -> f "[%s] -> [%s]"
                    (Uri.to_string uri) (Uri.to_string new_uri));
      let headers =
        Cohttp.Header.init_with "location" (Uri.to_string new_uri)
      in
      Http.respond ~headers ~status:`Moved_permanently ~body:`Empty ()
  end

  module Dns_stuff = struct
    module D = Dns_mirage.Make(S)

    let dns_update ?ip zone host =
      let open Dns in
      let open Dns.Rr_map in
      let zone = Packet.Question.create zone Soa
      and update =
        let up =
          Domain_name.Map.singleton (Domain_name.raw host)
            (Packet.Update.Remove (K A) ::
             match ip with None -> [] | Some ip ->
               [ Packet.Update.Add (B (A, (3600l, Ipv4_set.singleton ip))) ])
        in
        (Domain_name.Map.empty, up)
      and header =
        let id = Randomconv.int16 R.generate in
        (id, Packet.Flags.empty)
      in
      Packet.create header zone (`Update update)

    let send_recv stack dns_ip dnskey keyname packet =
      let now = Ptime.v (C.now_d_ps ()) in
      match Dns_tsig.encode_and_sign ~proto:`Tcp packet now dnskey keyname with
      | Error e ->
        Logs.err (fun m -> m "error while constructing nsupdate: %a" Dns_tsig.pp_s e);
        Lwt.return (Error ())
      | Ok (data, mac) ->
        S.TCP.create_connection (S.tcp stack) (dns_ip, 53) >>= function
        | Error e ->
          Logs.err (fun m -> m "error establishing TCP connection to nameserver: %a"
                       S.TCP.pp_error e);
          Lwt.return (Error ())
        | Ok flow ->
          D.send_tcp flow data >>= function
          | Error () ->
            Logs.err (fun m -> m "error sending TCP data to nameserver");
            Lwt.return (Error ())
          | Ok () ->
            D.read_tcp (D.of_flow flow) >>= function
            | Error () ->
              Logs.err (fun m -> m "error receiving TCP reply from nameserver");
              Lwt.return (Error ())
            | Ok data ->
              match Dns_tsig.decode_and_verify now dnskey keyname ~mac data with
              | Error e ->
                Logs.err (fun m -> m "error decoding TSIG answer: %a" Dns_tsig.pp_e e);
                Lwt.return (Error ())
              | Ok (res, _, _) ->
                match Dns.Packet.reply_matches_request ~request:packet res with
                | Ok `Update_ack -> Lwt.return (Ok ())
                | Ok r ->
                  Logs.err (fun m -> m "error with dns packet: unexpected reply %a"
                               Dns.Packet.pp_reply r);
                  Lwt.return (Error ())
                | Error e ->
                  Logs.err (fun m -> m "error with dns packet: bad reply %a: %a"
                               Dns.Packet.pp_mismatch e Dns.Packet.pp res);
                  Lwt.return (Error ())

    let register_hostname stack dns_ip zone keyname dnskey host =
      let ip = Ipaddr.V4.Prefix.address (Key_gen.ipv4 ()) in
      let packet = dns_update ~ip zone host in
      send_recv stack dns_ip dnskey keyname packet

    let deregister_hostname stack dns_ip zone keyname dnskey host =
      let packet = dns_update zone host in
      send_recv stack dns_ip dnskey keyname packet
  end

  module LE = struct
    module HTTP_client = struct
      module Headers = Cohttp.Header
      module Body = Cohttp_lwt.Body

      module Response = struct
        include Cohttp.Response
        let status resp = Cohttp.Code.code_of_status (Cohttp.Response.status resp)
      end

      include Http_client
    end
    module Acme = Letsencrypt.Client.Make(HTTP_client)

    let gen_rsa ?seed () =
      let g = match seed with
        | None -> None
        | Some seed ->
          let seed = Cstruct.of_string seed in
          Some (Mirage_crypto_rng.(create ~seed (module Fortuna)))
      in
      Mirage_crypto_pk.Rsa.generate ?g ~bits:4096 ()

    module HTTP_solver = struct
      let prefix = ".well-known", "acme-challenge"

      let dispatch token content request _body =
        let path = Uri.path (Cohttp.Request.uri request) in
        Logs.info (fun m -> m "let's encrypt dispatcher %s" path);
        match Astring.String.cuts ~sep:"/" ~empty:false path with
        | [ p1; p2; token' ] when
            String.equal p1 (fst prefix) && String.equal p2 (snd prefix) &&
            String.equal token token' ->
          let headers =
            Cohttp.Header.init_with "content-type" "application/octet-stream"
          in
          Http.respond ~headers ~status:`OK ~body:(`String content) ()
        | _ -> Http.respond ~status:`Not_found ~body:`Empty ()

      let solver http_server _host ~prefix:_ ~token ~content =
        Lwt.async (fun () -> http_server (`TCP 80) (serve (dispatch token content)));
        Lwt.return (Ok ())
    end

    module ALPN_solver = struct
      let alpn_protocols = ["acme-tls/1"]

      let solver stack _host ~alpn:_ priv cert =
        let open Lwt.Infix in
        let certificates = `Single ([cert], priv) in
        let tls_config = Tls.Config.server ~alpn_protocols ~certificates () in
        S.listen_tcp stack ~port:443 (fun tcp_flow ->
            TLS.server_of_flow tls_config tcp_flow >>= function
            | Ok flow -> TLS.close flow
            | Error we ->
              Logs.err (fun m -> m "error establishing TLS session: %a"
                           TLS.pp_write_error we);
              Lwt.return_unit);
        Lwt.return (Ok ())
    end

    module DNS_solver = struct
      let update zone name value =
        let open Dns in
        let open Dns.Rr_map in
        let zone = Packet.Question.create zone Soa
        and update =
          let up =
            Domain_name.Map.singleton name
              [ Packet.Update.Remove (K Txt) ;
                Packet.Update.Add (B (Txt, (3600l, Txt_set.singleton value))) ]
          in
          (Domain_name.Map.empty, up)
        and header =
          let id = Randomconv.int16 R.generate in
          (id, Packet.Flags.empty)
        in
        Packet.create header zone (`Update update)

      let solver stack dns_ip dnskey keyname zone name value =
        let packet = update zone name value in
        Dns_stuff.send_recv stack dns_ip dnskey keyname packet >|= function
        | Ok () -> Ok ()
        | Error () -> Error (`Msg "DNS error")
    end

    let csr key host =
      let cn =
        let h = Domain_name.to_string host in
        X509.[Distinguished_name.(Relative_distinguished_name.singleton (CN h))]
      in
      X509.Signing_request.create cn key

    let provision host stack http_server ctx dns =
      let open Lwt_result.Infix in
      let endpoint =
        if Key_gen.production () then
          Letsencrypt.letsencrypt_production_url
        else
          Letsencrypt.letsencrypt_staging_url
      and email = Key_gen.email ()
      and seed = Key_gen.account_seed ()
      in
      let priv = `RSA (gen_rsa ?seed:(Key_gen.cert_seed ()) ()) in
      match csr priv host with
      | Error (`Msg err) ->
        Logs.err (fun m -> m "couldn't create signing request %s" err);
        exit argument_error
      | Ok csr ->
        let solver = match Key_gen.challenge () with
          | "http" ->
            Logs.info (fun m -> m "listening on 80/HTTP (let's encrypt provisioning)");
            Letsencrypt.Client.http_solver (HTTP_solver.solver http_server)
          | "alpn" ->
            Logs.info (fun m -> m "ALPN challenge");
            Letsencrypt.Client.alpn_solver (ALPN_solver.solver stack)
          | "dns" ->
            begin match dns with
              | None ->
                Logs.info (fun m -> m "no DNS server and key provided");
                exit argument_error
              | Some (dns_ip, zone, keyname, dnskey) ->
                Logs.info (fun m -> m "DNS challenge");
                Letsencrypt_dns.dns_solver (DNS_solver.solver stack dns_ip dnskey keyname zone)
            end
          | s ->
            Logs.info (fun m -> m "unsupported challenge %s" s);
            exit argument_error
        in
        Acme.initialise ~ctx ~endpoint ?email (gen_rsa ?seed ()) >>= fun le ->
        let sleep sec = Time.sleep_ns (Duration.of_sec sec) in
        Acme.sign_certificate ~ctx solver le sleep csr >|= fun certs ->
        `Single (certs, priv)
  end

  let hostname () =
    let host = Key_gen.hostname () in
    match Domain_name.of_string host with
    | Error `Msg err ->
      Logs.err (fun m -> m "invalid hostname provided %s: %s" err host);
      exit argument_error
    | Ok h ->
      match Domain_name.host h with
      | Error `Msg err ->
        Logs.err (fun m -> m "invalid hostname provided %s: %s" err host);
        exit argument_error
      | Ok h -> h

  let dns_info () =
    match Key_gen.dns_server (), Key_gen.dns_key () with
    | None, _ | _, None ->
      Logs.warn (fun m -> m "no dns server or key provided, not registering hostname");
      None
    | Some dns_ip, Some k ->
      match Dns.Dnskey.name_key_of_string k with
      | Error `Msg msg ->
        Logs.err (fun m -> m "error %s parsing dns key: %s" msg k);
        exit argument_error
      | Ok (keyname, dnskey) ->
        match Dns_server.Authentication.zone_and_operation keyname with
        | None ->
          Logs.err (fun m -> m "error parsing zone of dns key %a"
                       Domain_name.pp keyname);
          exit argument_error
        | Some (zone, _) -> Some (dns_ip, zone, keyname, dnskey)

  let start () stack http_client http_server () () =
    let host = hostname () in
    let dns = dns_info () in
    (match dns with
     | None -> Lwt.return_unit
     | Some (dns_ip, zone, keyname, dnskey) ->
       Logs.info (fun m -> m "registering %a in DNS (%a)" Domain_name.pp host
                     Ipaddr.pp dns_ip);
       Dns_stuff.register_hostname stack dns_ip zone keyname dnskey host >|= function
       | Ok () -> ()
       | Error () -> exit argument_error) >>= fun () ->
    Logs.info (fun m -> m "provisioning a lets encrypt certificate");
    LE.provision host stack http_server http_client dns >>= (function
        | Ok certificates ->
          Logs.info (fun m -> m "received certificate chain");
          let tls = `TLS (Tls.Config.server ~certificates (), `TCP 443) in
          let https =
            Logs.info (fun f -> f "listening on 443/HTTPS");
            http_server tls (serve HTTP_Server.dispatch)
          and http =
            Logs.info (fun f -> f "listening on 80/HTTP, redirecting to 443/HTTPS");
            http_server (`TCP 80) (serve HTTP_Server.redirect)
          in
          Logs.info (fun m -> m "serving HTTP for 5 seconds");
          let after_5 = Time.sleep_ns (Duration.of_sec 5) in
          Lwt.pick [ http ; https ; after_5 ]
        | Error `Msg msg ->
          Logs.info (fun m -> m "received error %s while provisioning" msg);
          Lwt.return_unit) >>= fun () ->
    match dns with
    | None -> Lwt.return_unit
    | Some (dns_ip, zone, keyname, dnskey) ->
      Logs.info (fun m -> m "deregistering %a in DNS (%a)" Domain_name.pp host
                    Ipaddr.pp dns_ip);
      Dns_stuff.deregister_hostname stack dns_ip zone keyname dnskey host >|= function
      | Ok () -> ()
      | Error () -> exit argument_error
end
