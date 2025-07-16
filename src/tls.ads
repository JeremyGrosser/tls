pragma Ada_2012;

pragma Style_Checks (Off);
pragma Warnings (Off, "-gnatwu");
pragma Warnings (Off, "-gnatwi");

with Interfaces.C; use Interfaces.C;
with Interfaces.C.Strings;
with Interfaces;
with System.CRTL;
with System;
with GNAT.OS_Lib;

package TLS is

   TLS_API : constant := 20200120;  --  /usr/include/tls.h:37

   TLS_PROTOCOL_TLSv1_0 : constant := (2 ** 3);  --  /usr/include/tls.h:43
   TLS_PROTOCOL_TLSv1_1 : constant := (2 ** 3);  --  /usr/include/tls.h:44

   TLS_PROTOCOL_TLSv1_2 : constant := (2 ** 3);  --  /usr/include/tls.h:46
   TLS_PROTOCOL_TLSv1_3 : constant := (2 ** 4);  --  /usr/include/tls.h:47
   --  unsupported macro: TLS_PROTOCOL_TLSv1 (TLS_PROTOCOL_TLSv1_2|TLS_PROTOCOL_TLSv1_3)
   --  unsupported macro: TLS_PROTOCOLS_ALL TLS_PROTOCOL_TLSv1
   --  unsupported macro: TLS_PROTOCOLS_DEFAULT (TLS_PROTOCOL_TLSv1_2|TLS_PROTOCOL_TLSv1_3)

   TLS_WANT_POLLIN : constant := -2;  --  /usr/include/tls.h:55
   TLS_WANT_POLLOUT : constant := -3;  --  /usr/include/tls.h:56

   TLS_OCSP_RESPONSE_SUCCESSFUL : constant := 0;  --  /usr/include/tls.h:59
   TLS_OCSP_RESPONSE_MALFORMED : constant := 1;  --  /usr/include/tls.h:60
   TLS_OCSP_RESPONSE_INTERNALERROR : constant := 2;  --  /usr/include/tls.h:61
   TLS_OCSP_RESPONSE_TRYLATER : constant := 3;  --  /usr/include/tls.h:62
   TLS_OCSP_RESPONSE_SIGREQUIRED : constant := 4;  --  /usr/include/tls.h:63
   TLS_OCSP_RESPONSE_UNAUTHORIZED : constant := 5;  --  /usr/include/tls.h:64

   TLS_OCSP_CERT_GOOD : constant := 0;  --  /usr/include/tls.h:67
   TLS_OCSP_CERT_REVOKED : constant := 1;  --  /usr/include/tls.h:68
   TLS_OCSP_CERT_UNKNOWN : constant := 2;  --  /usr/include/tls.h:69

   TLS_CRL_REASON_UNSPECIFIED : constant := 0;  --  /usr/include/tls.h:72
   TLS_CRL_REASON_KEY_COMPROMISE : constant := 1;  --  /usr/include/tls.h:73
   TLS_CRL_REASON_CA_COMPROMISE : constant := 2;  --  /usr/include/tls.h:74
   TLS_CRL_REASON_AFFILIATION_CHANGED : constant := 3;  --  /usr/include/tls.h:75
   TLS_CRL_REASON_SUPERSEDED : constant := 4;  --  /usr/include/tls.h:76
   TLS_CRL_REASON_CESSATION_OF_OPERATION : constant := 5;  --  /usr/include/tls.h:77
   TLS_CRL_REASON_CERTIFICATE_HOLD : constant := 6;  --  /usr/include/tls.h:78
   TLS_CRL_REASON_REMOVE_FROM_CRL : constant := 8;  --  /usr/include/tls.h:79
   TLS_CRL_REASON_PRIVILEGE_WITHDRAWN : constant := 9;  --  /usr/include/tls.h:80
   TLS_CRL_REASON_AA_COMPROMISE : constant := 10;  --  /usr/include/tls.h:81

   TLS_MAX_SESSION_ID_LENGTH : constant := 32;  --  /usr/include/tls.h:83
   TLS_TICKET_KEY_SIZE : constant := 48;  --  /usr/include/tls.h:84

   type tls is null record;   -- incomplete struct

   type tls_config is null record;   -- incomplete struct

   type tls_read_cb is access function
        (arg1 : access tls;
         arg2 : System.Address;
         arg3 : Interfaces.C.size_t;
         arg4 : System.Address) return System.CRTL.ssize_t
   with Convention => C;  -- /usr/include/tls.h:89

   type tls_write_cb is access function
        (arg1 : access tls;
         arg2 : System.Address;
         arg3 : Interfaces.C.size_t;
         arg4 : System.Address) return System.CRTL.ssize_t
   with Convention => C;  -- /usr/include/tls.h:91

   function tls_init return int  -- /usr/include/tls.h:94
   with Import => True,
        Convention => C,
        External_Name => "tls_init";

   function tls_config_error (u_config : access tls_config) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:96
   with Import => True,
        Convention => C,
        External_Name => "tls_config_error";

   function tls_error (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:97
   with Import => True,
        Convention => C,
        External_Name => "tls_error";

   function tls_config_new return access tls_config  -- /usr/include/tls.h:99
   with Import => True,
        Convention => C,
        External_Name => "tls_config_new";

   procedure tls_config_free (u_config : access tls_config)  -- /usr/include/tls.h:100
   with Import => True,
        Convention => C,
        External_Name => "tls_config_free";

   function tls_default_ca_cert_file return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:102
   with Import => True,
        Convention => C,
        External_Name => "tls_default_ca_cert_file";

   function tls_config_add_keypair_file
     (u_config : access tls_config;
      u_cert_file : Interfaces.C.Strings.chars_ptr;
      u_key_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:104
   with Import => True,
        Convention => C,
        External_Name => "tls_config_add_keypair_file";

   function tls_config_add_keypair_mem
     (u_config : access tls_config;
      u_cert : access Interfaces.Unsigned_8;
      u_cert_len : Interfaces.C.size_t;
      u_key : access Interfaces.Unsigned_8;
      u_key_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:106
   with Import => True,
        Convention => C,
        External_Name => "tls_config_add_keypair_mem";

   function tls_config_add_keypair_ocsp_file
     (u_config : access tls_config;
      u_cert_file : Interfaces.C.Strings.chars_ptr;
      u_key_file : Interfaces.C.Strings.chars_ptr;
      u_ocsp_staple_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:108
   with Import => True,
        Convention => C,
        External_Name => "tls_config_add_keypair_ocsp_file";

   function tls_config_add_keypair_ocsp_mem
     (u_config : access tls_config;
      u_cert : access Interfaces.Unsigned_8;
      u_cert_len : Interfaces.C.size_t;
      u_key : access Interfaces.Unsigned_8;
      u_key_len : Interfaces.C.size_t;
      u_staple : access Interfaces.Unsigned_8;
      u_staple_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:111
   with Import => True,
        Convention => C,
        External_Name => "tls_config_add_keypair_ocsp_mem";

   function tls_config_set_alpn (u_config : access tls_config; u_alpn : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:114
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_alpn";

   function tls_config_set_ca_file (u_config : access tls_config; u_ca_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:115
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ca_file";

   function tls_config_set_ca_path (u_config : access tls_config; u_ca_path : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:116
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ca_path";

   function tls_config_set_ca_mem
     (u_config : access tls_config;
      u_ca : access Interfaces.Unsigned_8;
      u_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:117
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ca_mem";

   function tls_config_set_cert_file (u_config : access tls_config; u_cert_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:119
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_cert_file";

   function tls_config_set_cert_mem
     (u_config : access tls_config;
      u_cert : access Interfaces.Unsigned_8;
      u_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:121
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_cert_mem";

   function tls_config_set_ciphers (u_config : access tls_config; u_ciphers : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:123
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ciphers";

   function tls_config_set_crl_file (u_config : access tls_config; u_crl_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:124
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_crl_file";

   function tls_config_set_crl_mem
     (u_config : access tls_config;
      u_crl : access Interfaces.Unsigned_8;
      u_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:125
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_crl_mem";

   function tls_config_set_dheparams (u_config : access tls_config; u_params : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:127
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_dheparams";

   function tls_config_set_ecdhecurve (u_config : access tls_config; u_curve : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:128
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ecdhecurve";

   function tls_config_set_ecdhecurves (u_config : access tls_config; u_curves : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:129
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ecdhecurves";

   function tls_config_set_key_file (u_config : access tls_config; u_key_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:130
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_key_file";

   function tls_config_set_key_mem
     (u_config : access tls_config;
      u_key : access Interfaces.Unsigned_8;
      u_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:131
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_key_mem";

   function tls_config_set_keypair_file
     (u_config : access tls_config;
      u_cert_file : Interfaces.C.Strings.chars_ptr;
      u_key_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:133
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_keypair_file";

   function tls_config_set_keypair_mem
     (u_config : access tls_config;
      u_cert : access Interfaces.Unsigned_8;
      u_cert_len : Interfaces.C.size_t;
      u_key : access Interfaces.Unsigned_8;
      u_key_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:135
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_keypair_mem";

   function tls_config_set_keypair_ocsp_file
     (u_config : access tls_config;
      u_cert_file : Interfaces.C.Strings.chars_ptr;
      u_key_file : Interfaces.C.Strings.chars_ptr;
      u_staple_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:137
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_keypair_ocsp_file";

   function tls_config_set_keypair_ocsp_mem
     (u_config : access tls_config;
      u_cert : access Interfaces.Unsigned_8;
      u_cert_len : Interfaces.C.size_t;
      u_key : access Interfaces.Unsigned_8;
      u_key_len : Interfaces.C.size_t;
      u_staple : access Interfaces.Unsigned_8;
      staple_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:139
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_keypair_ocsp_mem";

   function tls_config_set_ocsp_staple_mem
     (u_config : access tls_config;
      u_staple : access Interfaces.Unsigned_8;
      u_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:142
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ocsp_staple_mem";

   function tls_config_set_ocsp_staple_file (u_config : access tls_config; u_staple_file : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:144
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_ocsp_staple_file";

   function tls_config_set_protocols (u_config : access tls_config; u_protocols : Interfaces.Unsigned_32) return int  -- /usr/include/tls.h:146
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_protocols";

   function tls_config_set_session_fd (u_config : access tls_config; u_session_fd : int) return int  -- /usr/include/tls.h:147
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_session_fd";

   function tls_config_set_verify_depth (u_config : access tls_config; u_verify_depth : int) return int  -- /usr/include/tls.h:148
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_verify_depth";

   procedure tls_config_prefer_ciphers_client (u_config : access tls_config)  -- /usr/include/tls.h:150
   with Import => True,
        Convention => C,
        External_Name => "tls_config_prefer_ciphers_client";

   procedure tls_config_prefer_ciphers_server (u_config : access tls_config)  -- /usr/include/tls.h:151
   with Import => True,
        Convention => C,
        External_Name => "tls_config_prefer_ciphers_server";

   procedure tls_config_insecure_noverifycert (u_config : access tls_config)  -- /usr/include/tls.h:153
   with Import => True,
        Convention => C,
        External_Name => "tls_config_insecure_noverifycert";

   procedure tls_config_insecure_noverifyname (u_config : access tls_config)  -- /usr/include/tls.h:154
   with Import => True,
        Convention => C,
        External_Name => "tls_config_insecure_noverifyname";

   procedure tls_config_insecure_noverifytime (u_config : access tls_config)  -- /usr/include/tls.h:155
   with Import => True,
        Convention => C,
        External_Name => "tls_config_insecure_noverifytime";

   procedure tls_config_verify (u_config : access tls_config)  -- /usr/include/tls.h:156
   with Import => True,
        Convention => C,
        External_Name => "tls_config_verify";

   procedure tls_config_ocsp_require_stapling (u_config : access tls_config)  -- /usr/include/tls.h:158
   with Import => True,
        Convention => C,
        External_Name => "tls_config_ocsp_require_stapling";

   procedure tls_config_verify_client (u_config : access tls_config)  -- /usr/include/tls.h:159
   with Import => True,
        Convention => C,
        External_Name => "tls_config_verify_client";

   procedure tls_config_verify_client_optional (u_config : access tls_config)  -- /usr/include/tls.h:160
   with Import => True,
        Convention => C,
        External_Name => "tls_config_verify_client_optional";

   procedure tls_config_clear_keys (u_config : access tls_config)  -- /usr/include/tls.h:162
   with Import => True,
        Convention => C,
        External_Name => "tls_config_clear_keys";

   function tls_config_parse_protocols (u_protocols : access Interfaces.Unsigned_32; u_protostr : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:163
   with Import => True,
        Convention => C,
        External_Name => "tls_config_parse_protocols";

   function tls_config_set_session_id
     (u_config : access tls_config;
      u_session_id : access unsigned_char;
      u_len : Interfaces.C.size_t) return int  -- /usr/include/tls.h:165
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_session_id";

   function tls_config_set_session_lifetime (u_config : access tls_config; u_lifetime : int) return int  -- /usr/include/tls.h:167
   with Import => True,
        Convention => C,
        External_Name => "tls_config_set_session_lifetime";

   function tls_config_add_ticket_key
     (u_config : access tls_config;
      u_keyrev : Interfaces.Unsigned_32;
      u_key : access unsigned_char;
      u_keylen : Interfaces.C.size_t) return int  -- /usr/include/tls.h:168
   with Import => True,
        Convention => C,
        External_Name => "tls_config_add_ticket_key";

   function tls_client return access tls  -- /usr/include/tls.h:171
   with Import => True,
        Convention => C,
        External_Name => "tls_client";

   function tls_server return access tls  -- /usr/include/tls.h:172
   with Import => True,
        Convention => C,
        External_Name => "tls_server";

   function tls_configure (u_ctx : access tls; u_config : access tls_config) return int  -- /usr/include/tls.h:173
   with Import => True,
        Convention => C,
        External_Name => "tls_configure";

   procedure tls_reset (u_ctx : access tls)  -- /usr/include/tls.h:174
   with Import => True,
        Convention => C,
        External_Name => "tls_reset";

   procedure tls_free (u_ctx : access tls)  -- /usr/include/tls.h:175
   with Import => True,
        Convention => C,
        External_Name => "tls_free";

   function tls_accept_fds
     (u_ctx : access tls;
      u_cctx : System.Address;
      u_fd_read : int;
      u_fd_write : int) return int  -- /usr/include/tls.h:177
   with Import => True,
        Convention => C,
        External_Name => "tls_accept_fds";

   function tls_accept_socket
     (u_ctx : access tls;
      u_cctx : System.Address;
      u_socket : int) return int  -- /usr/include/tls.h:179
   with Import => True,
        Convention => C,
        External_Name => "tls_accept_socket";

   function tls_accept_cbs
     (u_ctx : access tls;
      u_cctx : System.Address;
      u_read_cb : tls_read_cb;
      u_write_cb : tls_write_cb;
      u_cb_arg : System.Address) return int  -- /usr/include/tls.h:180
   with Import => True,
        Convention => C,
        External_Name => "tls_accept_cbs";

   function tls_connect
     (u_ctx : access tls;
      u_host : Interfaces.C.Strings.chars_ptr;
      u_port : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:182
   with Import => True,
        Convention => C,
        External_Name => "tls_connect";

   function tls_connect_fds
     (u_ctx : access tls;
      u_fd_read : int;
      u_fd_write : int;
      u_servername : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:183
   with Import => True,
        Convention => C,
        External_Name => "tls_connect_fds";

   function tls_connect_servername
     (u_ctx : access tls;
      u_host : Interfaces.C.Strings.chars_ptr;
      u_port : Interfaces.C.Strings.chars_ptr;
      u_servername : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:185
   with Import => True,
        Convention => C,
        External_Name => "tls_connect_servername";

   function tls_connect_socket
     (u_ctx : access tls;
      u_s : int;
      u_servername : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:187
   with Import => True,
        Convention => C,
        External_Name => "tls_connect_socket";

   function tls_connect_cbs
     (u_ctx : access tls;
      u_read_cb : tls_read_cb;
      u_write_cb : tls_write_cb;
      u_cb_arg : System.Address;
      u_servername : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:188
   with Import => True,
        Convention => C,
        External_Name => "tls_connect_cbs";

   function tls_handshake (u_ctx : access tls) return int  -- /usr/include/tls.h:190
   with Import => True,
        Convention => C,
        External_Name => "tls_handshake";

   function tls_read
     (u_ctx : access tls;
      u_buf : System.Address;
      u_buflen : Interfaces.C.size_t) return System.CRTL.ssize_t  -- /usr/include/tls.h:191
   with Import => True,
        Convention => C,
        External_Name => "tls_read";

   function tls_write
     (u_ctx : access tls;
      u_buf : System.Address;
      u_buflen : Interfaces.C.size_t) return System.CRTL.ssize_t  -- /usr/include/tls.h:192
   with Import => True,
        Convention => C,
        External_Name => "tls_write";

   function tls_close (u_ctx : access tls) return int  -- /usr/include/tls.h:193
   with Import => True,
        Convention => C,
        External_Name => "tls_close";

   function tls_peer_cert_provided (u_ctx : access tls) return int  -- /usr/include/tls.h:195
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_provided";

   function tls_peer_cert_contains_name (u_ctx : access tls; u_name : Interfaces.C.Strings.chars_ptr) return int  -- /usr/include/tls.h:196
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_contains_name";

   function tls_peer_cert_hash (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:198
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_hash";

   function tls_peer_cert_issuer (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:199
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_issuer";

   function tls_peer_cert_subject (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:200
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_subject";

   function tls_peer_cert_notbefore (u_ctx : access tls) return GNAT.OS_Lib.time_t  -- /usr/include/tls.h:201
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_notbefore";

   function tls_peer_cert_notafter (u_ctx : access tls) return GNAT.OS_Lib.time_t  -- /usr/include/tls.h:202
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_notafter";

   function tls_peer_cert_chain_pem (u_ctx : access tls; u_len : access Interfaces.C.size_t) return access Interfaces.Unsigned_8  -- /usr/include/tls.h:203
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_cert_chain_pem";

   function tls_conn_alpn_selected (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:205
   with Import => True,
        Convention => C,
        External_Name => "tls_conn_alpn_selected";

   function tls_conn_cipher (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:206
   with Import => True,
        Convention => C,
        External_Name => "tls_conn_cipher";

   function tls_conn_cipher_strength (u_ctx : access tls) return int  -- /usr/include/tls.h:207
   with Import => True,
        Convention => C,
        External_Name => "tls_conn_cipher_strength";

   function tls_conn_servername (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:208
   with Import => True,
        Convention => C,
        External_Name => "tls_conn_servername";

   function tls_conn_session_resumed (u_ctx : access tls) return int  -- /usr/include/tls.h:209
   with Import => True,
        Convention => C,
        External_Name => "tls_conn_session_resumed";

   function tls_conn_version (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:210
   with Import => True,
        Convention => C,
        External_Name => "tls_conn_version";

   function tls_load_file
     (u_file : Interfaces.C.Strings.chars_ptr;
      u_len : access Interfaces.C.size_t;
      u_password : Interfaces.C.Strings.chars_ptr) return access Interfaces.Unsigned_8  -- /usr/include/tls.h:212
   with Import => True,
        Convention => C,
        External_Name => "tls_load_file";

   procedure tls_unload_file (u_buf : access Interfaces.Unsigned_8; len : Interfaces.C.size_t)  -- /usr/include/tls.h:213
   with Import => True,
        Convention => C,
        External_Name => "tls_unload_file";

   function tls_ocsp_process_response
     (u_ctx : access tls;
      u_response : access unsigned_char;
      u_size : Interfaces.C.size_t) return int  -- /usr/include/tls.h:215
   with Import => True,
        Convention => C,
        External_Name => "tls_ocsp_process_response";

   function tls_peer_ocsp_cert_status (u_ctx : access tls) return int  -- /usr/include/tls.h:217
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_cert_status";

   function tls_peer_ocsp_crl_reason (u_ctx : access tls) return int  -- /usr/include/tls.h:218
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_crl_reason";

   function tls_peer_ocsp_next_update (u_ctx : access tls) return GNAT.OS_Lib.time_t  -- /usr/include/tls.h:219
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_next_update";

   function tls_peer_ocsp_response_status (u_ctx : access tls) return int  -- /usr/include/tls.h:220
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_response_status";

   function tls_peer_ocsp_result (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:221
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_result";

   function tls_peer_ocsp_revocation_time (u_ctx : access tls) return GNAT.OS_Lib.time_t  -- /usr/include/tls.h:222
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_revocation_time";

   function tls_peer_ocsp_this_update (u_ctx : access tls) return GNAT.OS_Lib.time_t  -- /usr/include/tls.h:223
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_this_update";

   function tls_peer_ocsp_url (u_ctx : access tls) return Interfaces.C.Strings.chars_ptr  -- /usr/include/tls.h:224
   with Import => True,
        Convention => C,
        External_Name => "tls_peer_ocsp_url";

end TLS;

pragma Style_Checks (On);
pragma Warnings (On, "-gnatwu");
