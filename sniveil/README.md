# SNIveil

Kişisel kullanım için basit bir Android VPN uygulaması. Sunucusuzdur: tüm
trafiği kendi cihazından normal (korunmuş) soketlerle gerçek hedefe iletir,
ama 443 portundaki TLS ClientHello'yu ISP'nin DPI'ı okumadan önce ikiye
böler (SNI fragmentation) ve isteğe bağlı olarak gerçek bağlantıdan hemen
önce, çok düşük TTL'li, hedefe hiç ulaşmayan bir "sahte ClientHello"
gönderir (SNI alanında ayarlarda yazdığın adresle).

## Gerçekçi beklenti

- **SNI fragmentation** (asıl koruma): root istemez, çoğu cihazda çalışır,
  birçok DPI kutusunu atlatır. Garantili değildir; bazı gelişmiş DPI'lar
  TCP segmentlerini birleştirip tekrar okur.
- **Sahte/decoy ClientHello**: ISP'nin sadece pasif olarak geçen
  ClientHello'ları SNI'ya göre loglayan bir sistemi varsa, bu paket
  "xxx.com'a gidiyor" izlenimini bırakır. TTL değerini (`decoyTtl`,
  varsayılan 4) kendi ağına göre ayarlaman gerekir: çok yüksekse gerçek
  sunucuya ulaşıp karışıklık yaratır, çok düşükse ISP'nin kendi
  ekipmanından önce ölür ve hiçbir şey görülmez. Bunu `SniFragVpnService.kt`
  içindeki `decoyTtl` değerini değiştirip derleyerek deneme-yanılma ile
  bulman gerekir.
- Bu teknikler ISP'nin IP adresini/portunu göremeyeceği anlamına gelmez —
  hangi IP'ye bağlandığını her zaman görür. Sadece **hangi hostname'e
  gittiğini (SNI) okuma/loglama** kısmını zorlaştırır/yanıltır.
- UDP (DNS dahil) şu an iletilmiyor; basitlik için bilerek bırakıldı. Bunu
  istersen ekleyebiliriz ama DNS sızıntısı istemiyorsan cihazının DNS
  ayarını elle DoH yapan bir uygulamaya (ör. tarayıcı içi DoH) bırakman
  daha sağlam olur.
- Bu minimal bir TCP relay'dir (tam bir TCP/IP yığını değil): yeniden
  gönderim veya tıkanıklık kontrolü yok. Kişisel test için yeterli, ama
  ağır yük altında bağlantı kopabilir.

## Derleme

### Yöntem 1: GitHub Actions (APK indirir)
1. Bu klasörü kendi GitHub repona push'la.
2. Actions sekmesinde "Build APK" workflow'u otomatik çalışır (ya da
   "Run workflow" ile elle tetikle).
3. Bittiğinde "Artifacts" altında `sniveil-debug-apk` dosyasını indir,
   içindeki `app-debug.apk`'yı telefonuna kur (Ayarlar > Güvenlik'ten
   "bilinmeyen kaynaklar"a izin vermen gerekebilir).

### Yöntem 2: Android Studio
1. Bu klasörü Android Studio ile aç (Gradle sync otomatik gradle wrapper'ı
   indirir, internet gerekir).
2. Build > Build Bundle(s)/APK(s) > Build APK(s).
3. `app/build/outputs/apk/debug/app-debug.apk` dosyasını telefonuna kur.

## Kullanım
1. Uygulamayı aç, "Sahte SNI" alanına ISP'nin zaten izin verdiği bir
   domain yaz (ör. `www.google.com`).
2. "İlk parça boyutu" — ClientHello'nun kaç byte'ının ilk pakette
   gideceği (varsayılan 2; çok küçük tutmak SNI'yı daha iyi gizler).
3. "Bağlan"a bas, Android'in VPN izni isteğini onayla.
4. Alttaki log alanında hangi bağlantıların parçalandığını görebilirsin.

## Hedef sürüm
`compileSdk`/`targetSdk = 35` (Android 15), `minSdk = 24`. Native (.so)
kütüphane kullanılmadığı için 16KB sayfa boyutu (Android 15+ cihazlar)
uyumluluğu otomatik; `app/build.gradle.kts` içindeki `packaging.jniLibs`
ayarı ileride native bağımlılık eklenirse hazır aligned paketlenmesini
garanti eder.
