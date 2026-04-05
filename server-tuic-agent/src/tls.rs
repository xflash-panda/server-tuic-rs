use std::{path::Path, sync::Arc};

use eyre::{Context, Result};
use rustls::{
	pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
	server::{ClientHello, ResolvesServerCert},
	sign::CertifiedKey,
};

#[derive(Debug)]
pub struct CertResolver {
	cert_key: Arc<CertifiedKey>,
}

impl CertResolver {
	pub async fn new(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
		let cert_key = load_cert_key(cert_path, key_path).await?;
		Ok(Arc::new(Self { cert_key }))
	}
}

impl ResolvesServerCert for CertResolver {
	fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		Some(self.cert_key.clone())
	}
}

pub async fn load_cert_key(cert_path: &Path, key_path: &Path) -> eyre::Result<Arc<CertifiedKey>> {
	let cert_chain = load_cert_chain(cert_path).await?;
	let der = load_priv_key(key_path).await?;
	#[cfg(feature = "aws-lc-rs")]
	let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der).context("Unsupported private key type")?;
	#[cfg(feature = "ring")]
	let key = rustls::crypto::ring::sign::any_supported_type(&der).context("Unsupported private key type")?;

	Ok(Arc::new(CertifiedKey::new(cert_chain, key)))
}

async fn load_cert_chain(cert_path: &Path) -> eyre::Result<Vec<CertificateDer<'static>>> {
	let data = tokio::fs::read(cert_path).await.context("Failed to read certificate chain")?;

	let pem_result = rustls_pemfile::certs(&mut data.as_slice())
		.collect::<Result<Vec<_>, _>>()
		.context("Invalid PEM certificate(s)");

	match pem_result {
		Ok(certs) if !certs.is_empty() => Ok(certs),
		_ => {
			if data.is_empty() {
				return Err(eyre::eyre!("Empty certificate file"));
			}
			Ok(vec![CertificateDer::from(data)])
		}
	}
}

async fn load_priv_key(key_path: &Path) -> eyre::Result<PrivateKeyDer<'static>> {
	let data = tokio::fs::read(key_path).await.context("Failed to read private key")?;

	if let Ok(Some(key)) = rustls_pemfile::private_key(&mut data.as_slice()).context("Malformed PEM private key") {
		return Ok(key);
	}

	if data.is_empty() {
		return Err(eyre::eyre!("Empty private key file"));
	}

	Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data)))
}

#[cfg(test)]
mod tests {
	use std::io::Write;

	use rcgen::{CertificateParams, DnType, KeyPair, SanType, string::Ia5String};
	use tempfile::NamedTempFile;

	use super::*;

	fn generate_test_cert() -> eyre::Result<(String, String)> {
		let mut params = CertificateParams::default();

		let mut distinguished_name = rcgen::DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "localhost");
		distinguished_name.push(DnType::OrganizationName, "My Company");
		distinguished_name.push(DnType::CountryName, "US");
		params.distinguished_name = distinguished_name;

		params.subject_alt_names = vec![
			SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
			SanType::IpAddress("127.0.0.1".parse()?),
		];
		let key_pair = KeyPair::generate()?;
		key_pair.serialize_der();

		let cert = params.self_signed(&key_pair)?;

		let private_key_pem = key_pair.serialize_pem();

		let cert_pem = cert.pem();

		Ok((cert_pem, private_key_pem))
	}

	fn generate_test_cert_der() -> eyre::Result<(Vec<u8>, Vec<u8>)> {
		let mut params = CertificateParams::default();

		let mut distinguished_name = rcgen::DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "localhost");
		distinguished_name.push(DnType::OrganizationName, "My Company");
		distinguished_name.push(DnType::CountryName, "US");
		params.distinguished_name = distinguished_name;

		params.subject_alt_names = vec![
			SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
			SanType::IpAddress("127.0.0.1".parse()?),
		];
		let key_pair = KeyPair::generate()?;

		let cert = params.self_signed(&key_pair)?;

		let private_key_der = key_pair.serialize_der();

		let cert_der = cert.der();

		Ok((cert_der.to_vec(), private_key_der))
	}

	async fn create_temp_cert_file(cert_data: &[u8], key_data: &[u8]) -> (NamedTempFile, NamedTempFile) {
		let mut cert_file = NamedTempFile::new().unwrap();
		cert_file.write_all(cert_data).unwrap();
		cert_file.as_file().sync_all().unwrap();

		let mut key_file = NamedTempFile::new().unwrap();
		key_file.write_all(key_data).unwrap();
		key_file.as_file().sync_all().unwrap();
		(cert_file, key_file)
	}

	#[tokio::test]
	async fn test_load_cert_chain_pem() -> Result<()> {
		let (cert_pem, _) = generate_test_cert()?;
		let (cert_file, _) = create_temp_cert_file(cert_pem.as_bytes(), b"").await;

		let result = load_cert_chain(cert_file.path()).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().len(), 1);
		Ok(())
	}

	#[tokio::test]
	async fn test_load_cert_chain_der() -> Result<()> {
		let (cert_der, _) = generate_test_cert_der()?;

		let (cert_file, _) = create_temp_cert_file(&cert_der, b"").await;

		let result = load_cert_chain(cert_file.path()).await?;
		assert_eq!(result.len(), 1);
		Ok(())
	}

	#[tokio::test]
	async fn test_load_priv_key_pem() -> Result<()> {
		let (_, key_pem) = generate_test_cert()?;
		let (_, key_file) = create_temp_cert_file(b"", key_pem.as_bytes()).await;

		let result = load_priv_key(key_file.path()).await;
		assert!(result.is_ok());
		Ok(())
	}

	#[tokio::test]
	async fn test_load_priv_key_der() -> Result<()> {
		let (_, key_der) = generate_test_cert_der()?;

		let (_, key_file) = create_temp_cert_file(b"", &key_der).await;

		let result = load_priv_key(key_file.path()).await;
		assert!(result.is_ok());
		Ok(())
	}

	#[tokio::test]
	async fn test_cert_resolver_load() -> Result<()> {
		let (cert_der, key_der) = generate_test_cert_der()?;
		let (cert_file, key_file) = create_temp_cert_file(&cert_der, &key_der).await;

		let resolver = CertResolver::new(cert_file.path(), key_file.path()).await.unwrap();

		assert!(!resolver.cert_key.cert.is_empty());
		Ok(())
	}

	#[tokio::test]
	async fn test_invalid_cert_handling() {
		let (cert_file, key_file) = create_temp_cert_file(b"invalid", b"invalid").await;

		let load_result = load_cert_key(cert_file.path(), key_file.path()).await;
		assert!(load_result.is_err());

		let resolver_result = CertResolver::new(cert_file.path(), key_file.path()).await;
		assert!(resolver_result.is_err());
	}
}
