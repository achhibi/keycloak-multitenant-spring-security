# Multi-Tenant OAuth2 Resource Server with Spring Security and Keycloak  

This project provides an advanced implementation of a multi-tenant OAuth2 resource server using **Spring Security** and **Keycloak**. It offers a robust architecture designed to handle authentication and authorization seamlessly across multiple tenants, leveraging the capabilities of Keycloak realms.  

## Key Features  

- **Multi-Tenant Support**  
  - Supports multiple tenants by mapping each tenant to a Keycloak realm.  
  - Dynamically resolves the tenant based on incoming requests, enabling isolated authentication and authorization for each realm.  

- **Authentication and Authorization**  
  - Implements OAuth2 standards for secure resource access.  
  - Fully integrated with Spring Security for a seamless security configuration.  
  - Validates access tokens issued by Keycloak, ensuring secure interaction between clients and the resource server.  

- **Scalable and Flexible**  
  - Designed to support a large number of tenants with minimal performance impact.  
  - Allows easy customization and integration with existing Spring Boot applications. 