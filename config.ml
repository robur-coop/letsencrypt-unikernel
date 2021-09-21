open Mirage

let hostname =
  let doc = Key.Arg.info ~doc:"Host name." ["hostname"] in
  Key.(create "hostname" Arg.(required string doc))

let production =
  let doc = Key.Arg.info ~doc:"Let's encrypt production environment." ["production"] in
  Key.(create "production" Arg.(opt bool false doc))

let cert_seed =
  let doc = Key.Arg.info ~doc:"Let's encrypt certificate seed." ["cert-seed"] in
  Key.(create "cert-seed" Arg.(opt (some string) None doc))

let cert_key_type =
  let doc = Key.Arg.info ~doc:"certificate key type" ["cert-key-type"] in
  Key.(create "cert-key-type" Arg.(opt string "RSA" doc))

let cert_bits =
  let doc = Key.Arg.info ~doc:"certificate public key bits" ["cert-bits"] in
  Key.(create "cert-bits" Arg.(opt int 4096 doc))

let account_seed =
  let doc = Key.Arg.info ~doc:"Let's encrypt account seed." ["account-seed"] in
  Key.(create "account-seed" Arg.(opt (some string) None doc))

let account_key_type =
  let doc = Key.Arg.info ~doc:"account key type" ["account-key-type"] in
  Key.(create "account-key-type" Arg.(opt string "RSA" doc))

let account_bits =
  let doc = Key.Arg.info ~doc:"account public key bits" ["account-bits"] in
  Key.(create "account-bits" Arg.(opt int 4096 doc))

let email =
  let doc = Key.Arg.info ~doc:"Let's encrypt E-Mail." ["email"] in
  Key.(create "email" Arg.(opt (some string) None doc))

let challenge =
  let doc = Key.Arg.info ~doc:"Let's encrypt challenge (http/alpn/dns)." ["challenge"] in
  Key.(create "challenge" Arg.(opt string "http" doc))

let dns_key =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
  Key.(create "dns-key" Arg.(opt (some string) None doc))

let dns_server =
  let doc = Key.Arg.info ~doc:"dns server IP" ["dns-server"] in
  Key.(create "dns-server" Arg.(opt (some ip_address) None doc))


let packages = [
  package "cohttp-mirage";
  package "tls-mirage";
  package "logs";
  package ~min:"0.4.0" "letsencrypt";
  package "letsencrypt-dns";
  package "dns-tsig";
  package "dns-server";
  package "dns-mirage";
  package "dns";
]

let stack = generic_stackv4v6 default_network

let conduit_ = conduit_direct ~tls:true stack
let http_srv = cohttp_server conduit_
let http_cli = cohttp_client (resolver_dns stack) conduit_

let () =
  let keys = Key.([
      abstract hostname; abstract production;
      abstract cert_seed; abstract cert_key_type; abstract cert_bits;
      abstract account_seed; abstract account_key_type; abstract account_bits;
      abstract email; abstract challenge;
      abstract dns_key; abstract dns_server;
    ])
  in
  register "letsencrypt" [
    foreign
      ~keys
      ~packages
      "Unikernel.Main"
      (random @-> stackv4v6 @-> http_client @-> http @-> pclock @-> time @-> job)
    $ default_random $ stack
    $ http_cli $ http_srv
    $ default_posix_clock
    $ default_time
  ]
