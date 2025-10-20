# Droid_SCEP
[![Play Store](.github/playstore-badge.svg)](https://play.google.com/store/apps/details?id=systems.sieber.droid_scep)
[![F-Droid](.github/fdroid-badge.svg)](https://f-droid.org/packages/systems.sieber.droid_scep)
[![APK Download](.github/apk-badge.svg)](https://github.com/schorschii/Droid_SCEP/releases)

Android SCEP (Simple Certificate Enrollment Protocol) client. Primarily intended for usage in open source MDM (Mobile Device Management) solutions like [OCO](https://github.com/schorschii/oco-server).

This is a fork of [Droid_Scep2](https://github.com/gjyoung1974/Droid_Scep2), with updated libraries, certificate poll, monitoring and MDM policy configuration support added.

It can (automatically) request an x509 certificate from a SCEP server such as [Microsoft's](http://social.technet.microsoft.com/wiki/contents/articles/9063.network-device-enrollment-service-ndes-in-active-directory-certificate-services-ad-cs.aspx) or [Cisco's Network Device Entrollment](http://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html) implementations.
