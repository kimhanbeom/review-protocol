//! Request handler for the server.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

use num_enum::FromPrimitive;
use oinq::request::parse_args;

use super::RequestCode;
use crate::types::{
    ColumnStatisticsUpdate, DataSource, DataSourceKey, EventMessage, HostNetworkGroup, LabelDb,
    OutlierInfo, TimeSeriesUpdate, UpdateClusterRequest, UserAgent,
};

/// A request handler that can handle a request to the server.
#[async_trait::async_trait]
pub trait Handler {
    async fn get_allowlist(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_blocklist(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_config(&self, _peer: &str) -> Result<String, String> {
        Err("not supported".to_string())
    }

    async fn get_data_source(
        &self,
        _key: &DataSourceKey<'_>,
    ) -> Result<Option<DataSource>, String> {
        Err("not supported".to_string())
    }

    async fn get_indicator(&self, _name: &str) -> Result<HashSet<Vec<String>>, String> {
        Err("not supported".to_string())
    }

    async fn get_internal_network_list(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_model(&self, _name: &str) -> Result<Vec<u8>, String> {
        Err("not supported".to_string())
    }

    async fn get_model_names(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_outliers(
        &self,
        _model_id: u32,
        _timestamp: i64,
    ) -> Result<Vec<(String, Vec<i64>)>, String> {
        Err("not supported".to_string())
    }

    async fn get_pretrained_model(&self, _name: &str) -> Result<Vec<u8>, String> {
        Err("not supported".to_string())
    }

    async fn get_labeldb_patterns(
        &self,
        _db_names: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<LabelDb>)>, String> {
        Err("not supported".to_string())
    }

    async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_trusted_domain_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn insert_column_statistics(
        &self,
        _statistics: &[ColumnStatisticsUpdate],
        _model_id: u32,
        _batch_ts: i64,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn insert_data_source(&self, _data_source: &DataSource) -> Result<u32, String> {
        Err("not supported".to_string())
    }

    async fn insert_event_labels(
        &self,
        _model_id: u32,
        _round: u32,
        _event_labels: &[EventMessage],
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn insert_model(&self, _model: &[u8]) -> Result<u32, String> {
        Err("not supported".to_string())
    }

    async fn insert_time_series(
        &self,
        _time_series: &[TimeSeriesUpdate],
        _model_id: u32,
        _batch_ts: i64,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn remove_model(&self, _name: &str) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn renew_certificate(&self, _peer: &str) -> Result<(String, String), String> {
        Err("not supported".to_string())
    }

    async fn update_clusters(
        &self,
        _input: &[UpdateClusterRequest],
        _model_id: u32,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn update_model(&self, _model: &[u8]) -> Result<u32, String> {
        Err("not supported".to_string())
    }

    async fn update_outliers(
        &self,
        _outliers: &[OutlierInfo],
        _model_id: u32,
        _timestamp: i64,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn update_host_ports(
        &self,
        _peer: &str,
        _hosts: &HashMap<IpAddr, HashMap<(u16, u8), u32>>,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn update_host_user_agents(
        &self,
        _peer: &str,
        _hosts: &[(IpAddr, Vec<UserAgent>, Vec<String>)],
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }
}

/// Handles requests to the server.
///
/// This handles only a subset of the requests that the server can receive. If
/// the request is not supported, the request code is returned to the caller.
///
/// # Errors
///
/// - There was an error reading from the stream.
/// - There was an error writing to the stream.
/// - An unknown request code was received.
/// - The arguments to the request were invalid.
#[allow(clippy::too_many_lines)]
pub async fn handle<H>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer: &str,
) -> io::Result<Option<(u32, Vec<u8>)>>
where
    H: Handler + Sync,
{
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        match RequestCode::from_primitive(code) {
            RequestCode::GetAllowlist => {
                parse_args::<()>(body)?;
                let result = handler.get_allowlist(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetBlocklist => {
                parse_args::<()>(body)?;
                let result = handler.get_blocklist(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDataSource => {
                let data_source_key = parse_args::<DataSourceKey>(body)?;
                let result = handler.get_data_source(&data_source_key).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetIndicator => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_indicator(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModelNames => {
                parse_args::<()>(body)?;
                let result = handler.get_model_names().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetLabelDbPatterns => {
                let db_names = parse_args::<Vec<(&str, &str)>>(body)?;
                let result = handler.get_labeldb_patterns(&db_names).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTorExitNodeList => {
                parse_args::<()>(body)?;
                let result = handler.get_tor_exit_node_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedDomainList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_domain_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedUserAgentList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_user_agent_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetConfig => {
                parse_args::<()>(body)?;
                let result = handler.get_config(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetInternalNetworkList => {
                parse_args::<()>(body)?;
                let result = handler.get_internal_network_list(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetOutliers => {
                let (model_id, timestamp) = parse_args::<(u32, i64)>(body)?;
                let result = handler.get_outliers(model_id, timestamp).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetPretrainedModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_pretrained_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertColumnStatistics => {
                let (statistics, model_id, batch_ts) =
                    parse_args::<(Vec<ColumnStatisticsUpdate>, u32, i64)>(body)?;
                let result = handler
                    .insert_column_statistics(&statistics, model_id, batch_ts)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertDataSource => {
                let data_source = parse_args::<DataSource>(body)?;
                let result = handler.insert_data_source(&data_source).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertEventLabels => {
                let (model_id, round, event_labels) =
                    parse_args::<(u32, u32, Vec<EventMessage>)>(body)?;
                let result = handler
                    .insert_event_labels(model_id, round, &event_labels)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertModel => {
                let body = parse_args::<Vec<u8>>(body)?;
                let result = handler.insert_model(&body).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertTimeSeries => {
                let (time_series, model_id, batch_ts) =
                    parse_args::<(Vec<TimeSeriesUpdate>, u32, i64)>(body)?;
                let result = handler
                    .insert_time_series(&time_series, model_id, batch_ts)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RemoveModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.remove_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RenewCertificate => {
                let result = handler.renew_certificate(peer).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateClusters => {
                let (input, model_id) = parse_args::<(Vec<UpdateClusterRequest>, u32)>(body)?;
                let result = handler.update_clusters(&input, model_id).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateModel => {
                let body = parse_args::<Vec<u8>>(body)?;
                let result = handler.update_model(&body).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateOutliers => {
                let (outliers, model_id, timestamp) =
                    parse_args::<(Vec<OutlierInfo>, u32, i64)>(body)?;
                let result = handler
                    .update_outliers(&outliers, model_id, timestamp)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateHostOpenedPorts => {
                let hosts = parse_args::<HashMap<IpAddr, HashMap<(u16, u8), u32>>>(body)?;
                let result = handler.update_host_ports(peer, &hosts).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateHostOsAgents => {
                let hosts = parse_args::<Vec<(IpAddr, Vec<UserAgent>, Vec<String>)>>(body)?;
                let result = handler.update_host_user_agents(peer, &hosts).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    send,
                    &mut buf,
                    Err("unknown request code") as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown request code",
                ));
            }
            _ => {
                return Ok(Some((code, body.into())));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::test::{TOKEN, channel};

    struct ModelHandler {
        insert_model_payload: Arc<Mutex<Option<Vec<u8>>>>,
        update_model_payload: Arc<Mutex<Option<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl Handler for ModelHandler {
        async fn insert_model(&self, model: &[u8]) -> Result<u32, String> {
            *self.insert_model_payload.lock().unwrap() = Some(model.to_vec());
            Ok(42)
        }

        async fn update_model(&self, model: &[u8]) -> Result<u32, String> {
            *self.update_model_payload.lock().unwrap() = Some(model.to_vec());
            Ok(55)
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn insert_and_update_model_deserialize_payload() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let insert_model_payload = Arc::new(Mutex::new(None));
        let update_model_payload = Arc::new(Mutex::new(None));

        let mut handler = ModelHandler {
            insert_model_payload: Arc::clone(&insert_model_payload),
            update_model_payload: Arc::clone(&update_model_payload),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            super::handle(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                "test-peer",
            )
            .await
        });

        let insert_payload = vec![0x10, 0x20, 0x30, 0x40];
        let insert_res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            insert_payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(insert_res.unwrap(), 42);

        let update_payload = vec![0x01, 0x02, 0x03];
        let update_res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::UpdateModel),
            update_payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(update_res.unwrap(), 55);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        match server_res {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
            Err(e) => panic!("unexpected server error: {e:?}"),
        }
        assert_eq!(*insert_model_payload.lock().unwrap(), Some(insert_payload));
        assert_eq!(*update_model_payload.lock().unwrap(), Some(update_payload));
    }
}
