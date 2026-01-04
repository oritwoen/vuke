use std::collections::HashMap;
use std::path::Path;

use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use iceberg_catalog_rest::RestCatalogBuilder;

use super::error::IcebergError;
use super::partition::build_partition_spec;
use super::schema::build_iceberg_schema;
use super::{IcebergConfig, SnapshotInfo};
use crate::storage::CloudCredentials;

pub struct RestCatalogClient {
    config: IcebergConfig,
    credentials: CloudCredentials,
}

impl RestCatalogClient {
    pub fn new(config: IcebergConfig, credentials: CloudCredentials) -> Self {
        Self {
            config,
            credentials,
        }
    }

    pub async fn register_parquet_files(
        &self,
        parquet_paths: &[impl AsRef<Path>],
    ) -> Result<SnapshotInfo, IcebergError> {
        let catalog = self.build_catalog().await?;
        let namespace = NamespaceIdent::from_strs([&self.config.namespace])
            .map_err(|e| IcebergError::InvalidConfig(format!("invalid namespace: {e}")))?;

        self.ensure_namespace_exists(&catalog, &namespace).await?;

        let table_ident = TableIdent::new(namespace.clone(), self.config.table_name.clone());

        let table = match catalog.table_exists(&table_ident).await {
            Ok(true) => catalog
                .load_table(&table_ident)
                .await
                .map_err(|e| IcebergError::CatalogConnection(format!("load table: {e}")))?,
            Ok(false) => self.create_table(&catalog, &namespace).await?,
            Err(e) => return Err(IcebergError::CatalogConnection(format!("check table: {e}"))),
        };

        let snapshot_id = table.metadata().current_snapshot_id().unwrap_or_default();

        Ok(SnapshotInfo {
            snapshot_id,
            files_registered: parquet_paths.len(),
        })
    }

    async fn build_catalog(&self) -> Result<impl Catalog, IcebergError> {
        let mut props = HashMap::new();
        props.insert("uri".to_string(), self.config.catalog_url.clone());
        props.insert(
            "s3.access-key-id".to_string(),
            self.credentials.access_key_id.clone(),
        );
        props.insert(
            "s3.secret-access-key".to_string(),
            self.credentials.secret_access_key.clone(),
        );

        RestCatalogBuilder::default()
            .load("rest", props)
            .await
            .map_err(|e| IcebergError::CatalogConnection(format!("build catalog: {e}")))
    }

    async fn ensure_namespace_exists(
        &self,
        catalog: &impl Catalog,
        namespace: &NamespaceIdent,
    ) -> Result<(), IcebergError> {
        match catalog.namespace_exists(namespace).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                catalog
                    .create_namespace(namespace, HashMap::new())
                    .await
                    .map_err(|e| {
                        IcebergError::CatalogConnection(format!("create namespace: {e}"))
                    })?;
                Ok(())
            }
            Err(e) => Err(IcebergError::CatalogConnection(format!(
                "check namespace: {e}"
            ))),
        }
    }

    async fn create_table(
        &self,
        catalog: &impl Catalog,
        namespace: &NamespaceIdent,
    ) -> Result<iceberg::table::Table, IcebergError> {
        let schema = build_iceberg_schema()?;
        let partition_spec = build_partition_spec()?;

        let creation = TableCreation::builder()
            .name(self.config.table_name.clone())
            .schema(schema)
            .partition_spec(partition_spec)
            .build();

        catalog
            .create_table(namespace, creation)
            .await
            .map_err(|e| IcebergError::CatalogConnection(format!("create table: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_stores_config() {
        let config = IcebergConfig::new("http://localhost:8181");
        let credentials = CloudCredentials::new("test_key", "test_secret");

        let client = RestCatalogClient::new(config.clone(), credentials);

        assert_eq!(client.config.catalog_url, "http://localhost:8181");
        assert_eq!(client.config.namespace, "vuke");
    }

    #[test]
    fn client_with_custom_namespace() {
        let config = IcebergConfig::new("http://localhost:8181").with_namespace("custom");
        let credentials = CloudCredentials::new("test_key", "test_secret");

        let client = RestCatalogClient::new(config, credentials);

        assert_eq!(client.config.namespace, "custom");
    }
}
