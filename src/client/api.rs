use std::io;

use serde::{de::DeserializeOwned, Serialize};

use super::Connection;
use crate::{
    server,
    types::{DataSource, DataSourceKey, HostNetworkGroup},
    unary_request,
};

/// The client API.
impl Connection {
    /// Fetches the configuration from the server.
    ///
    /// The format of the configuration is up to the caller to interpret.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_config(&self) -> io::Result<String> {
        let res: Result<String, String> = request(self, server::RequestCode::GetConfig, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of allowed networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_allow_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetAllowList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of blocked networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_block_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetBlockList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches a data source from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_data_source(&self, key: &DataSourceKey<'_>) -> io::Result<DataSource> {
        let res: Result<Option<DataSource>, String> =
            request(self, server::RequestCode::GetDataSource, key).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .and_then(|res| res.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
    }

    /// Fetches the list of internal networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_internal_network_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetInternalNetworkList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the patterns from the threat-intelligence database.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_tidb_patterns(
        &self,
        tidbs: &[(String, String)],
    ) -> io::Result<Vec<(String, Option<crate::types::Tidb>)>> {
        let res: Result<Vec<(String, Option<crate::types::Tidb>)>, String> =
            request(self, server::RequestCode::GetTidbPatterns, tidbs).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of Tor exit nodes from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_tor_exit_node_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTorExitNodeList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of trusted domains from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_domain_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedDomainList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the list of trusted user agents from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_user_agent_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedUserAgentList, ()).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the pretrained model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_pretrained_model(&self, name: &str) -> io::Result<Vec<u8>> {
        let res: Result<Vec<u8>, String> =
            request(self, server::RequestCode::GetPretrainedModel, name).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Fetches the renew certificate from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn renew_certificate(&self, cert: &[u8]) -> io::Result<(String, String)> {
        let res: Result<(String, String), String> =
            request(self, server::RequestCode::RenewCertificate, cert).await?;
        res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

async fn request<I, O>(conn: &Connection, code: server::RequestCode, input: I) -> io::Result<O>
where
    I: Serialize,
    O: DeserializeOwned,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    unary_request(&mut send, &mut recv, u32::from(code), input).await
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use crate::{
        server::handle,
        test::{TestServerHandler, TEST_ENV},
        types::{DataSourceKey, EventCategory, TiKind, TiRule, Tidb},
    };

    #[tokio::test]
    async fn get_data_source() {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            let mut handler = TestServerHandler;
            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            handle(&mut handler, &mut send, &mut recv).await?;
            Ok(()) as std::io::Result<()>
        });

        let client_res = client_conn.get_data_source(&DataSourceKey::Id(5)).await;
        assert!(client_res.is_ok());
        let received_data_source = client_res.unwrap();
        assert_eq!(received_data_source.name, "name5");

        let server_res = server_handle.await.unwrap();
        assert!(server_res.is_ok());

        test_env.teardown(server_conn);
    }

    #[tokio::test]
    async fn get_tidb_patterns() {
        use crate::server::RequestCode;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let db_names = vec![
            ("db1".to_string(), "table1".to_string()),
            ("db2".to_string(), "table2".to_string()),
        ];
        let patterns = vec![
            (
                "db1".to_string(),
                Some(Tidb {
                    id: 1,
                    name: "name1".to_string(),
                    description: Some("description1".to_string()),
                    kind: TiKind::Token,
                    category: EventCategory::Execution,
                    version: "1.0.0".to_string(),
                    patterns: vec![TiRule {
                        rule_id: 9,
                        category: EventCategory::Unknown,
                        name: "rule1".to_string(),
                        description: Some("description1".to_string()),
                        references: Some(vec!["ref1".to_string()]),
                        samples: Some(vec!["sample1".to_string()]),
                        signatures: Some(vec!["sig1".to_string()]),
                    }],
                }),
            ),
            ("db2".to_string(), None),
        ];

        let handler_conn = server_conn.clone();
        let server_patterns = patterns.clone();
        let server_handle = tokio::spawn(async move {
            use anyhow::{anyhow, Context};
            use bincode::Options;
            use num_enum::FromPrimitive;

            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            let mut buf = Vec::with_capacity(size_of::<u32>());
            let codec = bincode::DefaultOptions::new();
            let (code, body) = oinq::message::recv_request_raw(&mut recv, &mut buf)
                .await
                .unwrap();
            if RequestCode::from_primitive(code) != RequestCode::GetTidbPatterns {
                return Err(anyhow!("unexpected request code"));
            }
            let db_names = codec
                .deserialize::<Vec<(&str, &str)>>(body)
                .context("invalid argument")?;
            if db_names != db_names {
                return Err(anyhow!("unexpected database names"));
            }
            crate::server::respond_with_tidb_patterns(&mut send, &server_patterns).await?;

            Ok(())
        });

        let client_res = client_conn.get_tidb_patterns(&db_names).await;
        assert!(client_res.is_ok());
        let received_patterns = client_res.unwrap();
        assert_eq!(received_patterns.len(), patterns.len());
        for (i, (name, _)) in received_patterns.iter().enumerate() {
            assert_eq!(name, &patterns[i].0);
        }
        let server_res = server_handle.await.unwrap();
        assert!(server_res.is_ok());

        test_env.teardown(server_conn);
    }
}
