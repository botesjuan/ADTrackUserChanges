# AD Track User Changes  

>This is a CyberSecurity Identity and Access Management tool I wrote to do AD Tracking of User Changes.  

The PowerShell Script runs on schedule collecting Active Directory Security Event logs below and store in Microsoft SQL Database:  

* 4720 - user account was created
* 4722 – A user account was enabled
* 4725 – A user account was disabled
* 4726 - account was deleted
* 4728 – A member was added to a security global group
* 4729 - member was removed from a security-enabled global group
* 4732 – A member was added to a security local group
* 4733 - member was removed from a security-enabled local group
* 4737 - Security-enabled global group was changed
* 4738 – A User account was changed
    
* 4746 - A member was added to a security-disabled local group.
* 4747 - a member was removed from a security-disabled local group
* 4756 - A member was added to a security-enabled universal group
* 4757 - Member was removed from a security-enabled universal group
* 4758 - A security-enabled universal group was deleted
* 4759 - security-disabled universal group was created
* 4760 - security-disabled universal group was changed
* 4761 - member was added to a security-disabled universal group
* 4762 - member was removed from a security-disabled universal group
* 4763 - security-disabled universal group was deleted

>[Microsoft Document](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)  

>The powershell script captures the AD logs before they wrap as the amount of security events on busy time period result in logs being lost for historical records.
>The script have section perfoming a Health Check of Track AD Changes and SQL Table Check email send once a month.  

## Self Service Portal  

>The web portal is running on legacy Windows IIS  

```
c:\inetpub\wwwroot\SelfService
```  

>HTML Index page to portal:

```HTML
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!--[if IE]>
    <link rel="icon" href="/SelfService/favicon.ico">
  <![endif]-->

  <link href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700|Material+Icons" rel="stylesheet">
  <title>Self Service</title>

  <!-- Prefetch CSS -->
  <link href="/SelfService/css/chunk-01151f32.9643bc80.css" rel="prefetch">
  <link href="/SelfService/css/chunk-27f22b22.1c611692.css" rel="prefetch">
  <link href="/SelfService/css/chunk-2844d519.07315bd8.css" rel="prefetch">
  <link href="/SelfService/css/chunk-61cc5c53.45b7406d.css" rel="prefetch">
  <link href="/SelfService/css/chunk-78e9eda8.3a42f1cf.css" rel="prefetch">

  <!-- Prefetch JS -->
  <link href="/SelfService/js/chunk-01151f32.c07f5485.js" rel="prefetch">
  <link href="/SelfService/js/chunk-15604ca7.fd5031d2.js" rel="prefetch">
  <link href="/SelfService/js/chunk-1ed4cb8b.e1ca7613.js" rel="prefetch">
  <link href="/SelfService/js/chunk-27f22b22.275fab29.js" rel="prefetch">
  <link href="/SelfService/js/chunk-2844d519.2d4ca235.js" rel="prefetch">
  <link href="/SelfService/js/chunk-2d2133a5.bb2e7718.js" rel="prefetch">
  <link href="/SelfService/js/chunk-2d2371ed.e518e1e1.js" rel="prefetch">
  <link href="/SelfService/js/chunk-2f182b40.4d1aaee0.js" rel="prefetch">
  <link href="/SelfService/js/chunk-61cc5c53.f9bbe06e.js" rel="prefetch">
  <link href="/SelfService/js/chunk-6d26f21d.b0d63af3.js" rel="prefetch">
  <link href="/SelfService/js/chunk-78e9eda8.43ed98be.js" rel="prefetch">
  <link href="/SelfService/js/chunk-7fe304fa.e0498095.js" rel="prefetch">
  <link href="/SelfService/js/chunk-acd810b6.3c49202b.js" rel="prefetch">

  <!-- Preload CSS -->
  <link href="/SelfService/css/app.232966a0.css" rel="preload" as="style">
  <link href="/SelfService/css/chunk-vendors.3d47ecdb.css" rel="preload" as="style">

  <!-- Preload JS -->
  <link href="/SelfService/js/app.1038495e.js" rel="preload" as="script">
  <link href="/SelfService/js/chunk-vendors.fa8e4e51.js" rel="preload" as="script">

  <!-- Stylesheets -->
  <link href="/SelfService/css/chunk-vendors.3d47ecdb.css" rel="stylesheet">
  <link href="/SelfService/css/app.232966a0.css" rel="stylesheet">

  <!-- Icons and Manifest -->
  <link rel="icon" type="image/png" sizes="32x32" href="/SelfService/img/icons/favicon-32x32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/SelfService/img/icons/favicon-16x16.png">
  <link rel="manifest" href="/SelfService/manifest.json">
  <meta name="theme-color" content="#4DBA87">
  <meta name="apple-mobile-web-app-capable" content="no">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="infraselfsrv_ui">
  <link rel="apple-touch-icon" href="/SelfService/img/icons/apple-touch-icon-152x152.png">
  <link rel="mask-icon" href="/SelfService/img/icons/safari-pinned-tab.svg" color="#4DBA87">
  <meta name="msapplication-TileImage" content="/SelfService/img/icons/msapplication-icon-144x144.png">
  <meta name="msapplication-TileColor" content="#000000">
</head>

<body>
  <noscript>
    <strong>We're sorry but InfraSelfSrv_UI doesn't work properly without JavaScript enabled. Please enable it to continue.</strong>
  </noscript>
  <div id="app"></div>
  
  <script src="/SelfService/js/chunk-vendors.fa8e4e51.js"></script>
  <script src="/SelfService/js/app.1038495e.js"></script>
</body>

</html>
```  
