# OpenID4VCI Issuer - GCBA

Este proyecto es un **Emisor de Credenciales Verificables** basado en el estándar **OpenID4VCI**, diseñado para emitir la "Credencial Ciudadana" del Gobierno de la Ciudad de Buenos Aires (GCBA). Está construido sobre el ecosistema **Credo-TS** y utiliza **HashiCorp Vault** como proveedor de seguridad criptográfica.

## 🚀 Características Principales

- **Protocolo**: [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (V1.0).
- **Formato de Credencial**: [SD-JWT-VC](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt) (Selective Disclosure JWT).
- **Key Management (KMS)**: Integración personalizada con **HashiCorp Vault Transit Engine**.
- **Almacenamiento**: Persistencia robusta en **PostgreSQL**.
- **Seguridad**: Soporte para verificación de pruebas de posesión de clave (Proof of Possession) y vinculación de DID del Holder.
- **Compatibilidad**: Optimizado para la billetera **Paradym** (Android/iOS).

## 🛠️ Arquitectura Técnica

### Componentes Clave
- **`VaultKeyManagementModule`**: Una implementación personalizada del KMS de Credo que centraliza la creación de llaves y firmas en Vault, evitando que las llaves privadas salgan del HSM/Vault.
- **Mapping de IDs**: Incluye un sistema de traducción para sincronizar los identificadores internos de Credo (Base58 fingerprints) con los nombres de llaves en Vault.
- **SD-JWT Signature Support**: Validador criptográfico integrado para el formato `IEEE P1363` (específico para firmas ECDSA de JWT) utilizando el módulo nativo `crypto` de Node.js.

### Carpetas del Proyecto
- `src/infrastructure/agent`: Configuración y construcción del agente Credo.
- `src/infrastructure/keyManagement`: Lógica del KMS con Vault.
- `src/presentation/issuer`: Servicios de emisión y endpoints de configuración (`.well-known`).
- `src/app.ts`: Punto de entrada que inicializa el servidor express y las rutas de OpenID4VC.

## ⚙️ Configuración del Entorno

El proyecto requiere un archivo `.env` con las siguientes variables:

```env
PORT=3000
DOMAIN='https://<tu-subdominio>.ngrok-free.app'
VAULT_TOKEN='tu-root-token'
VAULT_ADDR='http://localhost:8200'
# Opcional: VAULT_TRANSIT_PATH='transit'
```

## 🏃 Ejecución

### Requisitos Previos
1. **HashiCorp Vault**: Corriendo con el `transit` engine habilitado (`vault secrets enable transit`).
2. **PostgreSQL**: Base de datos disponible para persistencia.
3. **Ngrok**: O cualquier túnel para exponer el dominio HTTPS necesario para `did:web`.

### Comandos
1. **Instalar dependencias**:
   ```bash
   npm install
   ```
2. **Modo Desarrollo**:
   ```bash
   npm run dev
   ```
3. **Producción**:
   ```bash
   npm run start
   ```

## 📋 Flujo de Emisión con Paradym
1. El servidor arranca y pre-registra su `did:web` en la base de datos.
2. Al iniciar, se genera una **Credential Offer** (visible en consola con un QR link).
3. Escanee el código QR con Paradym.
4. Ingrese el **PIN** que se muestra en la consola del servidor.
5. El servidor validará la prueba de la billetera y emitirá la **Credencial Ciudadana** firmada por el GCBA.

---
*Desarrollado para entornos de identidad digital soberana (SSI) y ecosistemas OpenID4VC.*
