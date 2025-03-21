pub mod ldap {
    use std::time::Duration;
    use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};

    pub struct LDAP {
        pub base_dn: String,
        pub conn_security: ConnSecurity,
        bind_credentials: Option<[String;2]>,
        conn: LdapConn,
        bound: bool
    }

    pub enum ConnSecurity {
        Tls,StartTls,None,TlsNoVerify,StartTlsNoVerify
    }


    impl LDAP {
        pub fn new(host: String, port: Option<u16>, conn_security: ConnSecurity, base_dn: String,
            bind: Option<[String;2]>) -> LDAP {

            let mut scheme: &str = "ldap";
            let mut settings: LdapConnSettings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10));

            match conn_security{
                ConnSecurity::Tls => {
                    scheme = "ldaps";

                }
                ConnSecurity::StartTls => {
                    settings = settings.set_starttls(true);
                }
                ConnSecurity::None => {
                    //WARN USER OF UNSAFE CONNECTION
                }
                ConnSecurity::TlsNoVerify => {
                    //WARN USER OF UNSAFE CONNECTION
                    scheme = "ldaps";
                    settings = settings.set_no_tls_verify(true);
                }
                ConnSecurity::StartTlsNoVerify => {
                    //WARN USER OF UNSAFE CONNECTION
                    settings = settings.set_starttls(true).set_no_tls_verify(true);
                }
            }

            let mut _port = 0;
            if scheme == "ldap" {
                _port = port.unwrap_or(389);
            } else if scheme == "ldaps" {
                _port = port.unwrap_or(636);
            } else {
                panic!("No valid LDAP scheme found!");
            }

            let ldap = LdapConn::with_settings(settings, format!("{}://{}:{}", scheme,
                                                                 host.as_str(), _port).as_str())
                .unwrap();

            LDAP {
                base_dn,
                conn_security,
                bind_credentials: bind,
                conn: ldap,
                bound: false
            }
        }

        fn bind(&mut self) {
            if self.bind_credentials.is_some() && !self.bound {
                let _credentials = self.bind_credentials.clone().unwrap();
                let mut _res = self.conn.simple_bind(_credentials[0].as_str(),
                                                     _credentials[1].as_str());
                _res.unwrap();
                self.bound = true;
            }
        }

        pub fn close_connection(&mut self) {
            self.conn.unbind().unwrap();
        }

        pub fn list_units(&mut self, scope: Option<Scope>) {
            self.bind();
            let _result = self.conn.search(self.base_dn.as_str(), scope.unwrap_or(Scope::OneLevel),
                                              "(objectClass=organizationalUnit)",
                                              vec!["dn", "ou"]).unwrap().success().unwrap();

            for entry in _result.0 {
                let _entry = SearchEntry::construct(entry);
                println!("{}: {}",
                         _entry.dn,
                         _entry.attrs.get("ou").unwrap()[0]
                );
            }
        }

        pub fn get_security(&self) -> &ConnSecurity {
            &self.conn_security
        }
    }
}