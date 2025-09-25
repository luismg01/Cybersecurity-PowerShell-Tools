# Herramientas PowerShell para Ciberseguridad y Pentesting

## Resumen

Kit compacto y práctico de scripts PowerShell creado para consultores de seguridad y pentesters. Diseñado para ser ligero, fácil de usar y efectivo en entornos reales.

## ✨ Herramientas Incluidas

* Invoke-BasicADScanner — Escáner básico para malas configuraciones comunes y ajustes débiles en Active Directory.

* Get-CriticalSecurityEvents — Recolector y analizador de eventos importantes del registro de seguridad de Windows (salida a CSV/JSON).

* Invoke-BasicObfuscation — Utilidad pequeña con técnicas básicas de ofuscación (reverse, Base64, wrappers simples).

## Requisitos

* Windows (cliente o servidor) con PowerShell. Los scripts son compatibles con **PowerShell 5.1** y posteriores.

* Para consultas de Active Directory: **módulo ActiveDirectory (RSAT)** disponible en la máquina o ejecutar en un Controlador de Dominio.

* Ejecutar PowerShell como **Administrador** para acceder al registro Security y otras funcionalidades.

## 🚀 Inicio rápido

1. Clona o copia el repositorio en tu máquina de análisis.

2. Abre PowerShell como Administrador.

3. Ejemplos:

### Ejecutar el escáner de AD y guardar CSV
```
.\Invoke-BasicADScanner.ps1 -OutputPath .\AD_Audit_Report.csv
```

### Recolectar eventos críticos de seguridad de los últimos 2 días y guardar JSON
```
.\Get-CriticalSecurityEvents.ps1 -Days 2 -OutputPath .\events.json
```

### Cargar la función de ofuscación y usarla interactivamente
```
. .\Invoke-BasicObfuscation.ps1
Invoke-BasicObfuscation -Command "Write-Host 'Hola Mundo'"
```
Consejo: Usa dot-sourcing (. .\script.ps1) cuando quieras cargar funciones en la sesión actual.

## Características y notas

* Uso de parsing XML de eventos para extraer campos de forma robusta e independiente del idioma (por ejemplo TargetUserName, ProcessName).

* Soporta exportación en .csv y .json.

* Para cobertura AD óptima, ejecutar scripts de AD/Directory en un Controlador de Dominio o recopilar eventos centralizados desde los DCs.

* Ajusta las listas de IDs de eventos y las ventanas temporales según tu entorno y niveles de ruido.

## ⚠️ Aviso legal y ético

Estas herramientas se proporcionan únicamente para evaluaciones de seguridad autorizadas y pruebas de penetración legales. No las ejecutes contra sistemas para los que no tengas permiso explícito — el uso no autorizado es ilegal y poco ético.

## 📎 Sugerencias y siguientes pasos

* Usa una VM dedicada o un jump box para análisis.

* Centraliza los resultados en un SIEM o almacenamiento compartido para triage e informes.

* Integra los resultados en pipelines CSV/JSON o conviértelos a ECS/CEF para ingestión en SIEMs.

## Contribución

Las contribuciones son bienvenidas. Por favor, abre problemas o solicitudes con mejoras, scripts adicionales o mejor parseo/formateo para tu entorno.

## Licencia

Licencia MIT — usar bajo su responsabilidad.

## 📞 Contacto

*Luis Miguel Martín González* - [luismiguelmartingonzalez@gmail.com](mailto:luismiguelmartingonzalez@gmail.com) - [Perfil de LinkedIn](https://www.linkedin.com/in/luismiguelmartingonzalez/)
