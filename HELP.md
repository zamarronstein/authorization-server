# Authorization Server

Este proyecto implementa un servidor de autorización basado en el protocolo OAuth 2.0. Proporciona servicios de autenticación y autorización para proteger los recursos de una aplicación.

## Características

- Implementación del flujo de autorización OAuth 2.0.
- Gestión de tokens de acceso y tokens de actualización.

## Requisitos Previos

Asegúrese de tener instalado en su sistema:

- Java JDK 17 o superior
- Maven

## Configuración

1. Clone este repositorio:

    ```bash
    git clone https://github.com/zamarronstein/authorization-server.git
    ```

2. Navegue al directorio del proyecto:

    ```bash
    cd authorization-server
    ```

3. Configure las propiedades del servidor en el archivo `application.properties`.

## Variables de Ambiente

| ID | Nombre de la Variable | Descripción                                                               | Valor                                          |
|----|-----------------------|---------------------------------------------------------------------------|------------------------------------------------|
| 1  | ISSUER_URI            | URI del emisor del token JWT                                              | https://authorization-server.azurewebsites.net |
| 2  | REDIRECT_URI          | URI de la dirección a la que redirecciona una vez que el login es exitoso | https://oauthdebugger.com/debug                |

## Ejecución Local

Siga estos pasos para ejecutar el servidor de autorización localmente:

1. Compile el proyecto con Maven:

    ```bash
    mvn clean install
    ```

2. Ejecute la aplicación:

    ```bash
    mvn spring-boot:run
    ```

El servidor de autorización estará disponible de acuerdo a lo que establezca en USER_URI, si trabaja en local puede establecer el valor `http://localhost:9000`. Puede ajustar el puerto en el archivo `application.properties`.

## Uso

Para obtener un token de acceso, siga el flujo de autorización especificado en la documentación del protocolo OAuth 2.0.

## Contribuciones

¡Las contribuciones son bienvenidas! Si desea contribuir a este proyecto, abra un problema o envíe una solicitud de extracción.

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE).

---