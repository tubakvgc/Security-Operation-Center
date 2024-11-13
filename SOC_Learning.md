**IOC ve IOA**

Kompromize Göstergeleri (IOC) ve Saldırı Göstergeleri (IOA), güvenlik olaylarını tespit etmek, anlamak ve bunlara yanıt vermek için kullanılan kritik kavramlardır.

### Kompromize Göstergeleri (IOC)

- **Tanım:** IOC'ler, potansiyel bir ihlal veya kötü niyetli faaliyetleri işaret eden adli veri parçalarıdır. Bir ağda veya işletim sistemlerinde gözlemlenen ve bir güvenlik olayı gerçekleşmiş olabileceğini gösteren artefaktlardır.
- **Örnekler:**
    - Alışılmadık ağ trafiği
    - Zararlı kod imzaları
    - Bilinen tehditlerle ilişkilendirilen IP adresleri, URL'ler veya alan adları
- **Kullanım:** IOC'ler, geçmişteki ve devam eden sızmaları tespit etmekte yardımcı olur. Genellikle bir ihlal tespit edildikten sonra kullanılan reaktif güvenlik önlemlerinde kullanılırlar.

### Saldırı Göstergeleri (IOA)

- **Tanım:** IOA'lar, saldırganların hedeflerine ulaşmak için kullandıkları niyet ve yöntemleri tespit etmeye odaklanır. IOC'lerden farklı olarak, genellikle belirli ve statik değildirler; IOA'lar, saldırganın davranış ve taktiklerini anlamaya yönelik daha çok davranış tabanlıdır.
- **Örnekler:**
    - Bir saldırganın bir sistemi ele geçirmeye çalıştığını gösteren davranış kalıpları
    - Bilinen saldırı teknikleriyle örtüşen alışılmadık faaliyetler (örneğin, bir ağ içinde yatay hareket)
    - Normal kullanım kalıplarından sapmalar gösteren eylem dizileri
    - Meşru araçların olağandışı şekillerde kullanılması (örneğin, PowerShell kullanarak zararlı yazılım indirilmesi)
- **Kullanım:** IOA'lar, potansiyel saldırıları hasara yol açmadan önce tespit etmek ve önlemek için kullanılır. Proaktiftirler ve saldırganın strateji ve tekniklerini anlamada ve bunları hafifletmede yardımcı olurlar.

### Karşılaştırma

- **Odak:**
    - IOC'ler bir olayın kanıtıdır.
    - IOA'lar, davranışa dayalı potansiyel kötü niyetli faaliyetlerin göstergeleridir.
- **Zaman Çerçevesi:**
    - IOC'ler genellikle olay sonrası analizde kullanılır.
    - IOA'lar gerçek zamanlı veya yakın gerçek zamanlı tespit ve önleme için kullanılır.
- **Doğa:**
    - IOC'ler genellikle statik ve spesifiktir.
    - IOA'lar dinamik ve davranış temellidir.

### Tehdit İstihbaratı

Tehdit istihbaratı, bir organizasyonun güvenliğine yönelik potansiyel veya mevcut tehditler hakkında bilgi toplama, analiz etme ve bu bilgileri kullanma pratiğidir.

Tehdit istihbaratı, organizasyonların siber tehditleri anlamalarına, tahmin etmelerine ve bunlara karşı savunma yapmalarına yardımcı olan bağlam ve uygulanabilir içgörüler sağlar.

### Tehdit İstihbaratının Temel Unsurları

1. **Veri Toplama:**
    - **Kaynaklar:** Tehdit istihbaratı verileri, açık kaynak istihbaratı, karanlık ağ izleme, dahili günlükler, ağ trafiği, sosyal medya ve ticari tehdit istihbarat beslemeleri gibi çeşitli kaynaklardan toplanabilir.
    - **Veri Türleri:** Buna IOC'ler, IP adresleri, URL'ler, alan adları, zararlı yazılım hash'leri ve tehdit aktörleri ile onların taktik, teknik ve prosedürleri (TTP'ler) hakkındaki detaylar dahildir.
2. **Analiz:**
    - **Korelasyon ve Bağlam:** Toplanan verilerin korelasyonlarını, kalıplarını ve bağlamını analiz etmek.
    - **TTP'ler:** Gelecekteki saldırıları tahmin etmek ve hafifletmek için tehdit aktörlerinin taktik, teknik ve prosedürlerini anlamak.
3. **Kullanım:**
    - **Proaktif Savunma:** Tehdit istihbaratını kullanarak potansiyel tehditleri tahmin etmek ve önlemek, savunmaları güçlendirmek ve güvenlik duruşunu iyileştirmek.
    - **Olay Müdahalesi:** Olay sırasında ve sonrasında tehdit istihbaratını kullanarak saldırının doğasını anlamak, saldırganları tanımlamak ve uygun iyileştirme adımlarını atmak.

### Tehdit İstihbaratının Faydaları

- Daha Hızlı Yanıt
- Risk Azaltma
- Gelişmiş Tespit ve Önleme
- Bilinçli Karar Verme

### Sonuç

Tehdit istihbaratı, modern siber güvenlik stratejilerinin kritik bir bileşenidir. Potansiyel tehditler hakkında bilgi toplayarak, analiz ederek ve kullanarak, organizasyonlar siber saldırılara karşı daha iyi savunma yapabilir, olaylara daha etkili bir şekilde yanıt verebilir ve genel güvenlik duruşlarını iyileştirmek için bilinçli kararlar alabilirler.

### Bazı Bilinen Tehdit İstihbaratı Kaynakları:

1. IBM X-Force Exchange
2. Cisco Talos Intelligence
3. AbuseIPDB
4. VirusTotal

---

---

**Sistem Sertleştirme**

Sistem sertleştirme, bir bilgisayar sistemini güvenli hale getirme sürecidir ve bu süreç, sistemin zafiyet yüzeyini azaltarak gerçekleştirilir. Bu, potansiyel saldırı vektörlerini en aza indirmek için sistemin yapılandırılmasını, gereksiz hizmetlerin ve yazılımların kaldırılmasını ve tehditlere karşı koruma sağlamak için güvenlik önlemlerinin uygulanmasını içerir.

### Sistem Sertleştirme Adımları

1. **Gereksiz Hizmetleri ve Yazılımları Kaldırın:**
    - Gereksiz Hizmetleri Devre Dışı Bırakın.
    - Gereksiz Yazılımları Kaldırın.
2. **Güvenlik Yamaları ve Güncellemeleri Uygulayın:**
    - Düzenli Güncellemeler.
    - Otomatik Güncellemeler.
3. **Kullanıcı Hesapları ve Kimlik Doğrulama:**
    - Güçlü Parola Politikaları.
    - Yönetici Ayrıcalıklarını Sınırlayın.
    - Çok Faktörlü Kimlik Doğrulama (MFA).
4. **Ağ Güvenlik Önlemleri:**
    - **Güvenlik Duvarları:** Gelen ve giden trafiği önceden tanımlanmış güvenlik kurallarına göre kontrol etmek için güvenlik duvarlarını yapılandırın.
    - **Saldırı Tespit ve Önleme Sistemleri (IDPS):** Şüpheli faaliyetler için ağ trafiğini izlemek üzere IDPS konuşlandırın.
5. **Kayıt ve İzleme Uygulayın:**
    - Sistem Günlükleri.
    - İzleme Araçları.
6. **Veri Koruma:**
    - Şifreleme.
    - Yedekleme.

### Sistem Sertleştirmenin Faydaları

- **Azaltılmış Saldırı Yüzeyi:** Potansiyel giriş noktalarının sayısını en aza indirerek, sistem sertleştirme saldırganların zafiyetleri istismar etmesini zorlaştırır.
- **Performans:** Gereksiz hizmetlerin ve yazılımların kaldırılması, sistem performansını ve kararlılığını artırabilir.
- **Geliştirilmiş Güvenlik Duruşu.**

### Sonuç

Sistem sertleştirme, siber güvenlikte potansiyel tehditlere karşı sistemleri güvence altına alarak riskleri azaltmayı amaçlayan hayati bir uygulamadır. Sistem sertleştirme için en iyi uygulamaları takip ederek, organizasyonlar kritik varlıklarını koruyabilir, uyumluluğu sürdürebilir ve genel güvenlik duruşlarını iyileştirebilirler.

---

**Yetki Yükseltme**

Yetki yükseltme, birçok siber saldırıda kritik bir adımdır ve saldırganın düşük yetkili bir hesaptan (örneğin, standart bir kullanıcı) daha yüksek yetkili bir hesaba (örneğin, yönetici veya root) geçiş yapmasını sağlar.

### Yetki Yükseltme Türleri

1. **Dikey Yetki Yükseltme:** Saldırganın başlangıçta verilen yetkilerden daha yüksek seviyede yetkiler kazanması durumudur. Örneğin, normal bir kullanıcı hesabının yönetici hakları kazanması.
2. **Yatay Yetki Yükseltme:** Saldırganın, benzer yetkilere sahip diğer kullanıcıların kaynaklarına veya işlevlerine erişim sağlaması durumudur. Örneğin, başka bir kullanıcının verilerine veya hesabına erişim sağlamak.

### Yaygın Yetki Yükseltme Yöntemleri

1. **Yazılım Açıklarından Yararlanma:**
    - **Tampon Taşması (Buffer Overflow):** Bir tamponu taşırarak bitişik belleği aşırı yazma ve daha yüksek yetkilerle kötü amaçlı kod çalıştırma.
    - **Sıfır Gün Açıkları (Zero-day Exploits):** Bilinmeyen açıkları kullanarak yükseltilmiş erişim sağlama.
2. **Yanlış Yapılandırmalar:**
    - **Güvensiz İzinler:** Zayıf dosya veya dizin izinlerinden yararlanarak hassas verilere veya çalıştırılabilir dosyalara erişim sağlama.
3. **Kimlik Bilgileri Hırsızlığı:**
    - **Keylogger:** Yönetici kimlik bilgilerini yakalamak için tuş vuruşlarını kaydetme.
    - **Hash ile Kimlik Doğrulama (Pass-the-Hash):** Gerçek parolayı bilmeden hash değerlerini kullanarak kimlik doğrulama.
4. **Sosyal Mühendislik:**
    - **Phishing:** Kullanıcıları kimlik bilgilerini ifşa etmeleri veya yükseltilmiş erişim sağlayan kötü amaçlı yazılımları çalıştırmaları için kandırma.
5. **Kötü Amaçlı Yazılım:**
    - **Truva Atları ve Rootkitler.**

### Önleyici Tedbirler

1. **Yama Yönetimi.**
2. **Asgari Yetki İlkesi:**
3. **Güçlü Kimlik Doğrulama:** Çok Faktörlü Kimlik Doğrulama ve Güvenli Kimlik Bilgisi Depolama.

### Sonuç:

Yetki yükseltme, siber güvenlikte önemli bir tehdittir ve saldırganların hassas sistemlere ve verilere yetkisiz erişim sağlamasına olanak tanır. Kullanılan yöntemleri anlamak ve güçlü güvenlik önlemleri uygulamak, organizasyonların yetki yükseltme saldırılarıyla ilişkili riskleri azaltmasına yardımcı olabilir.

---

Tabii! İşte metnin Türkçe çevirisi:

---

**Kalıcılık (Persistence)**

Kalıcılık, saldırganların ele geçirilen bir sistemde, yeniden başlatmalar, kullanıcı çıkışları veya erişimlerini kesmeye yönelik diğer girişimlerden sonra bile varlıklarını sürdürmek için kullandıkları tekniklere atıfta bulunur.

### Kalıcılık Yöntemleri

1. **AutoStart Girdileri:**
    - **Kayıt Defteri Anahtarları (Windows):** Windows kayıt defteri anahtarlarını, kötü amaçlı programları başlangıçta çalıştıracak şekilde değiştirmek.
    - **Başlangıç Klasörleri (Windows):** Sistem açıldığında çalışacak şekilde başlangıç klasörlerine kötü amaçlı kısayollar yerleştirmek.
2. **Zamanlanmış Görevler:**
    - **Görev Zamanlayıcı (Windows):** Belirli zamanlarda veya aralıklarda kötü amaçlı yükleri çalıştıracak şekilde zamanlanmış görevler oluşturmak veya mevcut görevleri değiştirmek.
3. **Rootkitler:**
    - **Rootkitler:** Kötü amaçlı yazılımların varlığını gizlemek ve sürekli erişim sağlamak için rootkitler kurmak.
4. **Kullanıcı ve Sistem Hesapları:**
    - **Arka Kapı Hesapları:** Uzaktan erişim için yönetici ayrıcalıklarına sahip gizli kullanıcı hesapları oluşturmak.
    - **Kimlik Bilgisi Hırsızlığı:** Erişimi sürdürmek için meşru kimlik bilgilerini çalmak ve kullanmak.
5. **DLL Enjeksiyonu ve Kaçırma:**
    - **DLL Enjeksiyonu:** Meşru işlemlere kötü amaçlı kod enjekte etmek.
    - **DLL Kaçırma:** Meşru dinamik bağlantı kitaplıklarını (DLL) kötü amaçlı olanlarla değiştirmek.
6. **Ağ Tabanlı Kalıcılık:**
    - **Uzaktan Erişim Truva Atları (RAT'lar):** Ele geçirilen sistemler üzerinde uzaktan kontrol sağlamak için RAT'ları kullanmak.
    - **Komut ve Kontrol (C2) Kanalları:** Komutlar vermek ve verileri gizlice dışa aktarmak için gizli iletişim kanalları kurmak.

### Sonuç

Kalıcılık, gelişmiş siber saldırıların kritik bir bileşenidir ve saldırganların kontrolü sürdürmelerini ve zamanla hedeflerine ulaşmalarını sağlar. Kalıcılık mekanizmalarını anlamak ve tespit etmek, etkili olay müdahalesi ve sistem sertleştirme çabaları için esastır.

---

**Yatay Hareket (Lateral Movement)**

Yatay hareket, saldırganların bir sistemi ilk olarak ele geçirdikten sonra bir ağ içinde hareket etmek için kullandıkları tekniklere atıfta bulunur. Bu hareket, saldırganların ağa yayılmalarına, ek sistemlere ve verilere erişim sağlamalarına olanak tanır.

Yatay hareket, birçok gelişmiş kalıcı tehdit (APT) aşamasında kritik bir rol oynar ve genellikle meşru kimlik bilgileri ve araçlar kullanıldığı için tespit edilmesi zordur.

### Yatay Hareket Teknikleri

1. **Kimlik Bilgisi Çıkarma:**
    - **Tanım:** Ele geçirilen sistemlerden kimlik bilgilerini (kullanıcı adı ve parola) çıkarmak.
    - **Araçlar:** Saldırganlar, Mimikatz, Windows Credential Editor (WCE) gibi araçları kullanır.
2. **Hash ile Kimlik Doğrulama (Pass-the-Hash):** Şifrelenmiş kimlik bilgilerini çözmeye gerek kalmadan kimlik doğrulaması için kullanmak.
3. **Biletle Kimlik Doğrulama (Pass-the-Ticket):**
    - **Tanım:** Kerberos biletlerini kullanarak kimlik doğrulama.
    - **Yöntem:** Saldırganlar, Kerberos biletlerini (TGT veya TGS) bellekten çalar ve bunları ağdaki diğer sistemlere erişmek için kullanır.
4. **Uzaktan Komut Yürütme:**
    - **Araçlar:** Saldırganlar, uzaktaki sistemlerde komut çalıştırmak için PsExec, Windows Management Instrumentation (WMI), Remote Desktop Protocol (RDP) ve Secure Shell (SSH) gibi araçları kullanır.
5. **Hizmet Oluşturma:** Uzaktaki sistemlerde kalıcılığı sürdürmek veya kötü amaçlı kod çalıştırmak için hizmetler oluşturmak veya mevcut hizmetleri değiştirmek.

### Yatay Hareketin Tespiti ve Önlenmesi

1. **Ağ Segmentasyonu:** Saldırıların yayılmasını sınırlamak için ağı daha küçük segmentlere ayırmak.
2. **Asgari Yetki İlkesi.**
3. **İzleme ve Kayıt Tutma:** Ağı genelinde faaliyetleri izlemek ve şüpheli davranışları tespit etmek.
4. **Çok Faktörlü Kimlik Doğrulama (MFA).**
5. **Davranış Analizi.**
6. **Uç Nokta Tespit ve Yanıt (EDR).**
7. **Yama Yönetimi.**
8. **Düzenli Denetimler ve Sızma Testleri.**

### Sonuç:

Yatay hareket, saldırganların bir ağ içinde kontrollerini genişletmelerine ve erişimlerini sağlamalarına olanak tanıyan sofistike ve gizli bir siber saldırı aşamasıdır. Yatay hareket için kullanılan teknikleri anlamak ve güçlü tespit ve önleme önlemleri uygulamak, ağ güvenliğini artırmak ve gelişmiş tehditlere karşı korunmak için kritik öneme sahiptir.

---

Tabii! İşte metnin Türkçe çevirisi:

---

**SANS Olay Müdahale Adımları**

1. **Hazırlık (Preparation):**
    - **Politika ve Prosedürlerin Belirlenmesi:** Kuruluşun ihtiyaçlarına göre uyarlanmış olay müdahale politikalarını, prosedürlerini ve yönergelerini tanımlayın.
    - **Olay Müdahale Ekibini Kurma:** Olay müdahalesi için belirli roller ve sorumluluklara sahip bireylerden oluşan bir ekip belirleyin ve oluşturun.
    - **Araçlar ve Kaynaklar:** Olay tespiti, analizi ve müdahale için gerekli araçların, kaynakların ve teknolojilerin hazır olmasını sağlayın.
    - **Eğitim ve Farkındalık:** Olay müdahale ekibi üyeleri ve ilgili paydaşlar için düzenli eğitim oturumları ve farkındalık programları düzenleyin.
2. **Tanımlama (Identification):**
    - **Olay Bildirimi:** İzleme sistemlerinden, kullanıcılar veya otomatik tespit araçlarından potansiyel güvenlik olaylarına dair uyarıları veya raporları tespit edin ve alın.
    - **İlk Triage:** Olayın doğasını ve kapsamını belirlemek, müdahale eylemlerine öncelik vermek ve ön bilgi toplamak için ilk triage'ı gerçekleştirin.
3. **İzolasyon (Containment):**
    - **Olayı Sınırlama:** Olayın daha fazla zarar vermesini veya yayılmasını önlemek için gerekli sınırlama önlemlerini uygulayın, bu sırada temel iş operasyonlarını sürdürün.
    - **Yalıtım:** Etkilenen sistemleri veya ağları yalıtarak etkiyi en aza indirin ve saldırının altyapının diğer bölümlerine yayılmasını önleyin.
4. **Yok Etme (Eradication):**
    - **Kök Neden Analizi:** Olayın kök nedenini belirleyin ve saldırganın yararlandığı belirli güvenlik açıklarını veya zayıflıkları tespit edin.
    - **Düzeltme:** Kök nedeni ortadan kaldırmak ve benzer olayların gelecekte tekrar yaşanmasını önlemek için düzeltici eylemler, yamalar veya yapılandırmalar geliştirin ve uygulayın.
5. **Kurtarma (Recovery):**
    - **Veri Geri Yükleme:** Etkilenen sistemleri, verileri ve hizmetleri, yedeklerden veya diğer güvenli kaynaklardan bilinen iyi bir duruma geri yükleyin.
    - **Sistem Doğrulama:** Geri yüklenen sistemlerin ve verilerin bütünlüğünü ve işlevselliğini doğrulayarak, tam olarak çalışır ve güvenli olduklarından emin olun.
6. **Dersler (Lessons Learned):**
    - **Olay Sonrası İnceleme:** Olay müdahale sürecini analiz etmek, güçlü ve zayıf yönleri belirlemek ve elde edilen dersleri toplamak için olay sonrası bir inceleme veya değerlendirme oturumu düzenleyin.
    - **Dokümantasyon:** Bulguları, alınan eylemleri ve olay müdahale prosedürlerinde, politikalarında ve teknik kontrollerde iyileştirmeler için önerileri belgeleyin.
    - **Sürekli İyileştirme:** Olay sonrası elde edilen derslere dayalı olarak önerilen iyileştirmeleri ve güncellemeleri uygulayarak kuruluşun genel olay müdahale yeteneklerini artırın.
7. **Raporlama ve İletişim (Reporting and Communication):**
    - **İç Raporlama.**
    - **Dış Raporlama.**

---

**Günlük Türleri (Type of Logs)**

1. **Sistem Günlükleri**
    - **İşletim Sistemi Günlükleri:** İşletim sistemiyle ilgili olayları kaydeder, örneğin başlatma olayları, kapatma, çökme ve sistem güncellemeleri.
2. **Uygulama Günlükleri**
    - **Tanım:** Uygulamaların ve yazılımların işleyişine ilişkin olayları kaydeder.
    - **Örnekler:** Web sunucuları (Apache, Nginx), veritabanı sunucuları (MySQL, PostgreSQL) ve özel uygulamalardan gelen günlükler.
3. **Güvenlik Günlükleri**
    - **Tanım:** Kimlik doğrulama girişimleri, erişim kontrol kararları ve politika değişiklikleri gibi güvenlikle ilgili olayları kaydeder.
    - **Örnekler:** Güvenlik duvarı günlükleri, Saldırı Tespit/Önleme Sistemi (IDS/IPS) günlükleri, antivirüs günlükleri.
4. **Ağ Günlükleri**
    - **Tanım:** Ağ trafiği ve ağ cihazlarıyla ilgili olaylar hakkında veri toplar.
    - **Örnekler:** Yönlendirici ve anahtar günlükleri, VPN günlükleri, ağ akış verileri (NetFlow, sFlow).
5. **Web Sunucusu Günlükleri**
    - **Tanım:** Web sunucuları tarafından işlenen HTTP isteklerini ve yanıtlarını kaydeder.
    - **Örnekler:** Apache, Nginx, IIS gibi sunuculardan erişim günlükleri, hata günlükleri ve istek günlükleri.
6. **Veritabanı Günlükleri**
    - **Tanım:** Veritabanı işlemleri, sorguları ve işlemleriyle ilgili olayları kaydeder.
    - **Örnekler:** SQL sorgu günlükleri, işlem günlükleri, MySQL, Oracle, SQL Server gibi veritabanlarından hata günlükleri.
7. **E-posta Günlükleri**
    - **Tanım:** E-posta işlemlerini ve ilgili faaliyetleri kaydeder.
    - **Örnekler:** SMTP günlükleri, Postfix, Exchange gibi posta sunucusu günlükleri, spam filtre günlükleri.
8. **Kimlik Doğrulama Günlükleri**
    - **Tanım:** Kimlik doğrulama girişimleri ve sonuçları hakkında ayrıntılar toplar.
    - **Örnekler:** Giriş denemeleri, başarılı ve başarısız kimlik doğrulamalar, çok faktörlü kimlik doğrulama (MFA) olayları.
9. **Güvenlik Duvarı Günlükleri**
    - **Tanım:** Güvenlik duvarı kurallarına göre izin verilen veya engellenen trafiği kaydeder.
    - **Örnekler:** Paket günlükleri, bağlantı denemeleri, kural eşleşmeleri.
10. **IDS/IPS Günlükleri**
    - **Tanım:** Saldırı tespit ve önleme sistemleriyle ilgili uyarıları ve olayları kaydeder.
    - **Örnekler:** Snort günlükleri, Suricata günlükleri, uyarı günlükleri.
11. **Uç Nokta Günlükleri**
    - **Tanım:** Masaüstü bilgisayarlar ve dizüstü bilgisayarlar gibi uç nokta cihazlarındaki olayları ve faaliyetleri kaydeder.
    - **Örnekler:** Antivirüs taramaları, uç nokta tespit ve yanıt (EDR) günlükleri, uygulama kullanımı.

---

İşte metnin Türkçe çevirisi:

---

**Protokol Günlükleri (Protocol Logs)**

1. **HTTP/HTTPS Günlükleri**
    - **Erişim Günlükleri (Access Logs):**
        - **Zaman Damgası:** İsteğin tarih ve saati.
        - **İstemci IP Adresi:** İsteği yapan istemcinin IP adresi.
        - **HTTP Yöntemi:** Kullanılan yöntem (ör. GET, POST).
        - **İstek URI'si:** İstenen kaynak.
        - **HTTP Versiyonu:** Kullanılan HTTP protokolü versiyonu.
        - **Yanıt Durum Kodu:** Sunucu tarafından döndürülen HTTP durum kodu.
        - **Kullanıcı Aracısı (User-Agent):** İstemcinin tarayıcısı veya yazılımı hakkında bilgi.
        - **Referer:** Şu anki istenen sayfaya bağlantı verilen önceki web sayfasının URL'si.
        - **Gönderilen Veri (Bytes Sent):** İstemciye gönderilen veri miktarı.
    - **Hata Günlükleri (Error Logs):**
        - **Zaman Damgası:** Hatanın tarih ve saati.
        - **İstemci IP Adresi:** Hatanın meydana geldiği istemcinin IP adresi.
        - **Hata Mesajı:** Karşılaşılan hatanın tanımı.
        - **İstek URI'si:** Hatanın oluştuğu sırada istenen kaynak.
2. **DNS Günlükleri**
    - **Sorgu Günlükleri (Query Logs):**
        - **Zaman Damgası:** Sorgunun tarih ve saati.
        - **İstemci IP Adresi:** Sorguyu yapan istemcinin IP adresi.
        - **Sorgu Adı:** İstenen alan adı.
        - **Sorgu Türü:** DNS sorgusunun türü (ör. A, AAAA, MX).
        - **Yanıt Kodu:** Sorgunun durumunu belirten DNS yanıt kodu.
    - **Yanıt Günlükleri (Response Logs):**
        - **Zaman Damgası:** Yanıtın tarih ve saati.
        - **İstemci IP Adresi:** Sorguyu yapan istemcinin IP adresi.
        - **Sorgu Adı:** İstenen alan adı.
        - **Sorgu Türü:** DNS sorgusunun türü.
        - **Yanıt Verisi (Response Data):** DNS yanıtında döndürülen veri (ör. IP adresleri).
3. **SMTP Günlükleri**
    - **Mail Sunucu Günlükleri (Mail Server Logs):**
        - **Zaman Damgası:** E-posta işleminin tarih ve saati.
        - **İstemci IP Adresi:** Gönderen veya alan istemcinin IP adresi.
        - **Gönderen Adresi (Sender Address):** Gönderenin e-posta adresi.
        - **Alıcı Adresi (Recipient Address):** Alıcının e-posta adresi.
        - **Mesaj Kimliği (Message ID):** E-posta mesajı için benzersiz tanımlayıcı.
        - **Durum Kodu:** İşlemin sonucunu belirten SMTP durum kodu.
        - **Hata Mesajı:** Karşılaşılan herhangi bir hatanın tanımı.
4. **FTP Günlükleri**
    - **Transfer Günlükleri (Transfer Logs):**
        - **Zaman Damgası:** Dosya transferinin tarih ve saati.
        - **İstemci IP Adresi:** İstemcinin IP adresi.
        - **Kullanıcı Adı (Username):** İstemcinin kullanıcı adı.
        - **Komut (Command):** Yürütülen FTP komutu (ör. RETR, STOR).
        - **Dosya Yolu (File Path):** Transfer edilen dosyanın yolu.
        - **Transfer Boyutu (Transfer Size):** Transfer edilen dosyanın boyutu.
        - **Durum Kodu:** Transferin sonucu (ör. başarı, başarısızlık).
5. **SSH Günlükleri**
    - **Kimlik Doğrulama Günlükleri (Authentication Logs):**
        - **Zaman Damgası:** Giriş denemesinin tarih ve saati.
        - **İstemci IP Adresi:** Bağlanan istemcinin IP adresi.
        - **Kullanıcı Adı (Username):** Giriş denemesi için kullanılan kullanıcı adı.
        - **Kimlik Doğrulama Yöntemi (Authentication Method):** Kullanılan yöntem (ör. şifre, açık anahtar).
        - **Sonuç (Result):** Giriş denemesinin başarısı veya başarısızlığı.
    - **Komut Yürütme Günlükleri (Command Execution Logs):**
        - **Zaman Damgası:** Komut yürütmenin tarih ve saati.
        - **İstemci IP Adresi:** İstemcinin IP adresi.
        - **Kullanıcı Adı (Username):** Giriş yapmış kullanıcının kullanıcı adı.
        - **Komut (Command):** Yürütülen komut.
6. **IMAP/POP3 Günlükleri**
    - **Bağlantı Günlükleri (Connection Logs):**
        - **Zaman Damgası:** Bağlantının tarih ve saati.
        - **İstemci IP Adresi:** Bağlanan istemcinin IP adresi.
        - **Kullanıcı Adı (Username):** Bağlantı için kullanılan kullanıcı adı.
        - **Komut (Command):** Yürütülen komut (ör. LOGIN, FETCH).
        - **Sonuç (Result):** Komutun başarısı veya başarısızlığı.
7. **Kerberos Günlükleri**
    - **Bilet Verme Günlükleri (Ticket Granting Logs):**
        - **Zaman Damgası:** Bilet olayının tarih ve saati.
        - **İstemci IP Adresi:** İstemcinin IP adresi.
        - **Kullanıcı Adı (Username):** İstemcinin kullanıcı adı.
        - **Bilet Türü (Ticket Type):** Bilet türü (TGT veya hizmet bileti).
        - **Sonuç (Result):** Bilet verme veya kullanımının başarısı veya başarısızlığı.

---

Bu çeviri ile metni Türkçe olarak inceleyebilir ve kullanabilirsiniz. Eğer daha fazla yardıma ihtiyacınız olursa, buradayım!

**Windows Günlükleri**

Windows günlükleri, sistem olayları, kullanıcı aktiviteleri, güvenlik olayları ve uygulama davranışları hakkında ayrıntılı bilgi sağlar. Aşağıda farklı günlük türleri ve yaygın olarak görülen olay kimlikleri (Event IDs) hakkında bilgi bulabilirsiniz:

### 1. **Sistem Günlükleri (System Logs)**

- **Amacı:** İşletim sistemi ve bileşenleriyle ilgili olayları kaydeder.
- **Ortak Alanlar:**
    - **Tarih ve Saat:** Olayın gerçekleştiği zaman.
    - **Olay Kimliği (Event ID):** Olay için benzersiz bir kimlik.
    - **Kaynak (Source):** Olayı üreten bileşen.
    - **Düzey (Level):** Olayın ciddiyeti (ör. Bilgi, Uyarı, Hata, Kritik).
    - **Kullanıcı (User):** Olayla ilişkili kullanıcı hesabı, varsa.
    - **Bilgisayar (Computer):** Olayın gerçekleştiği bilgisayarın adı.
    - **Açıklama (Description):** Olay hakkında ayrıntılı bilgi.

### 2. **Uygulama Günlükleri (Application Logs)**

- **Amacı:** Sistemde çalışan yazılım uygulamalarıyla ilgili olayları kaydeder.
- **Ortak Alanlar:** Tarih ve Saat, Olay Kimliği, Kaynak, Düzey, Kullanıcı, Bilgisayar, Açıklama.

### 3. **Güvenlik Günlükleri (Security Logs)**

- **Amacı:** Başarılı ve başarısız giriş denemeleri, ayrıcalık kullanımı ve güvenlik ayarlarındaki değişiklikler dahil olmak üzere güvenlikle ilgili olayları kaydeder.
- **Ortak Alanlar:**
    - Tarih ve Saat, Olay Kimliği, Kaynak, Düzey, Kullanıcı, Bilgisayar, Açıklama.
    - **Kategori (Category):** Olayın kategorisi (ör. Giriş/Çıkış, Nesne Erişimi, Hesap Yönetimi).

### 4. **Kurulum Günlükleri (Setup Logs)**

- **Amacı:** Sistem ve uygulamaların kurulum ve yapılandırma olaylarını kaydeder.
- **Ortak Alanlar:** Tarih ve Saat, Olay Kimliği, Kaynak, Düzey, Kullanıcı, Bilgisayar, Açıklama.

### Yaygın Olay Kimlikleri ve Açıklamaları

### **Güvenlik Günlükleri**

- **4624:** Bir hesap başarıyla oturum açtı.
- **4625:** Bir hesap oturum açmada başarısız oldu.
- **4648:** Açık kimlik bilgileri kullanılarak oturum açma girişiminde bulunuldu.
- **4672:** Yeni bir oturuma özel ayrıcalıklar verildi.
- **4720:** Bir kullanıcı hesabı oluşturuldu.
- **4723:** Bir hesabın şifresini değiştirme girişiminde bulunuldu.
- **4740:** Bir kullanıcı hesabı kilitlendi.

### **Sistem Günlükleri**

- **6005:** Olay günlüğü hizmeti başlatıldı.
- **6006:** Olay günlüğü hizmeti durduruldu.
- **6008:** Önceki sistem kapatılması beklenmedikti.
- **41:** Sistem, temiz bir şekilde kapatılmadan önce yeniden başlatıldı (Kernel-Power).

### **Uygulama Günlükleri**

- **1000:** Uygulama hatası.
- **1001:** Windows Hata Raporlama.

### **Hesap Yönetimi Olay Kimlikleri (Account Management Event IDs)**

- **4722:** Bir kullanıcı hesabı etkinleştirildi.
- **4723:** Bir hesabın şifresini değiştirme girişiminde bulunuldu.
- **4724:** Bir hesabın şifresi sıfırlanmaya çalışıldı.
- **4725:** Bir kullanıcı hesabı devre dışı bırakıldı.
- **4726:** Bir kullanıcı hesabı silindi.
- **4732:** Güvenlikle etkinleştirilmiş yerel bir gruba üye eklendi.
- **4733:** Güvenlikle etkinleştirilmiş yerel bir gruptan üye çıkarıldı.
- **4738:** Bir kullanıcı hesabı değiştirildi.
- **4740:** Bir kullanıcı hesabı kilitlendi.
- **4741:** Bir bilgisayar hesabı oluşturuldu.
- **4742:** Bir bilgisayar hesabı değiştirildi.
- **4743:** Bir bilgisayar hesabı silindi.
- **4756:** Güvenlikle etkinleştirilmiş evrensel bir gruba üye eklendi.
- **4757:** Güvenlikle etkinleştirilmiş evrensel bir gruptan üye çıkarıldı.
- **4767:** Bir kullanıcı hesabının kilidi açıldı.

### **Zamanlanmış Görevler (Scheduled Tasks)**

- **4698:** Zamanlanmış bir görev oluşturuldu.
- **4699:** Zamanlanmış bir görev silindi.
- **4700:** Zamanlanmış bir görev etkinleştirildi.
- **4701:** Zamanlanmış bir görev devre dışı bırakıldı.
- **4702:** Zamanlanmış bir görev güncellendi.

### **Denetim Politikası Değişiklikleri (Audit Policy Changes)**

- **4719:** Sistem denetim politikası değiştirildi.
- **4902:** Kullanıcı başına denetim politikası tablosu oluşturuldu.
- **4904:** Bir güvenlik olay kaynağını kaydetme girişiminde bulunuldu.
- **4905:** Bir güvenlik olay kaynağını kayıttan çıkarma girişiminde bulunuldu.

### **İşlem Takibi Olayları (Process Tracking Events)**

- **4688:** Yeni bir işlem oluşturuldu.
- **4689:** Bir işlem sonlandı.

Bu olay kimlikleri, Windows sisteminde gerçekleşen olayları izlemek ve analiz etmek için kullanışlıdır. Sisteminizi korumak ve güvenlik olaylarını zamanında tespit edebilmek için bu günlüklerin düzenli olarak gözden geçirilmesi önemlidir.

**Kerberos ve Güvenlik Hesap Yöneticisi (SAM) Hakkında**

### **Kerberos**

Kerberos, istemci-sunucu uygulamaları için güçlü kimlik doğrulama sağlamak amacıyla gizli anahtar şifrelemesi kullanan bir ağ kimlik doğrulama protokolüdür.

### **Ana Bileşenler:**

- **Kimlik Doğrulama Sunucusu (AS):**
    - İlk kimlik doğrulama işlemini gerçekleştirir ve Ticket Granting Service (TGS) için bilet verir.
- **Veritabanı:**
    - Kimlik Doğrulama Sunucusu, kullanıcıların erişim haklarını veritabanında doğrular.
- **Bilet Veren Sunucu (TGS):**
    - Kullanıcının istekte bulunduğu sunucuya erişim sağlamak için bilet verir.

### **Kerberos Genel Bakış:**

1. **Adım-1:**
    - Kullanıcı sisteme giriş yapar ve bir hizmet talebinde bulunur. Bu, bilet veren hizmet için bir talep anlamına gelir.
2. **Adım-2:**
    - Kimlik Doğrulama Sunucusu, kullanıcının erişim haklarını veritabanını kullanarak doğrular ve bilet verme bileti (TGT) ve oturum anahtarı verir. Sonuçlar, kullanıcının şifresiyle şifrelenir.
3. **Adım-3:**
    - Kullanıcı, mesajı şifresiyle çözer ve bileti Bilet Veren Sunucu'ya gönderir. Bilet, kullanıcı adı ve ağ adresleri gibi kimlik doğrulayıcıları içerir.
4. **Adım-4:**
    - Bilet Veren Sunucu, kullanıcının gönderdiği bileti ve kimlik doğrulayıcıyı doğrular ve sunucudan hizmet talep etmek için gerekli bileti oluşturur.
5. **Adım-5:**
    - Kullanıcı, bileti ve kimlik doğrulayıcıyı sunucuya gönderir.
6. **Adım-6:**
    - Sunucu, bileti ve kimlik doğrulayıcıyı doğrular ve ardından kullanıcıya hizmete erişim sağlar. Kullanıcı, artık hizmetlere erişebilir.

### **Yaygın Kerberos Saldırıları:**

1. **Pass-the-Ticket (PtT):**
    - Saldırganlar, ele geçirilen sistemden Kerberos biletlerini çalar ve bunları ağdaki diğer sistemlere kimlik doğrulama için kullanır. Bu, şifre gibi kimlik bilgilerine ihtiyaç duymadan kimlik doğrulama yapılmasını sağlar.
2. **Pass-the-Hash (PtH):**
    - Şifrelenmiş kimlik bilgilerini (şifre hash'lerini) çalmak ve bir kullanıcı olarak kimlik doğrulaması yapmak için kullanılır. Bu saldırı, NTLM ile daha yaygın olmakla birlikte, benzer prensipler Kerberos ortamlarına da uygulanabilir.
3. **Overpass-the-Hash (Pass-the-Key):**
    - Saldırganlar, NTLM hash'lerini kullanarak Kerberos biletleri talep eder. Bu saldırı, PtH ve PtT elemanlarını birleştirerek NTLM hash'leri kullanarak Kerberos biletleri elde edilmesini sağlar.
4. **Golden Ticket Saldırısı:**
    - Saldırganlar, süresiz bir son kullanma tarihine ve yüksek ayrıcalıklara (ör. domain yöneticisi) sahip sahte bir TGT oluşturur. Bu, yüksek yetkili Kerberos Ticket Granting Ticket (KRBTGT) hesap hash'inin ele geçirilmesini gerektirir.

### **Kerberos Saldırılarına Karşı Koruma:**

1. **Güçlü Şifre Politikaları:**
    - Tüm hesaplar, özellikle hizmet ve ayrıcalıklı hesaplar için güçlü ve karmaşık şifreler zorunlu hale getirilmelidir.
2. **Düzenli Hesap Denetimleri:**
    - Hesaplar düzenli olarak denetlenmeli ve doğru izinler ve etkinlikler açısından gözden geçirilmelidir.
3. **Yetkilerin Sınırlandırılması:**
    - En az ayrıcalık ilkesine uyulmalı ve hesapların yalnızca ihtiyaç duydukları erişim haklarına sahip olmaları sağlanmalıdır.
4. **Çok Faktörlü Kimlik Doğrulama (MFA):**
    - Ek bir güvenlik katmanı eklemek için MFA uygulanmalıdır.
5. **İzleme ve Tespit:**
    - Kerberos biletleri ve kimlik doğrulama süreçlerindeki olağandışı davranışları ve potansiyel saldırıları tespit etmek için güvenlik izleme araçları kullanılmalıdır.
6. **Yama ve Güncelleme:**
    - Sistemler ve yazılımlar, bilinen güvenlik açıklarını gidermek için en son yamalarla güncellenmelidir.

---

### **Güvenlik Hesap Yöneticisi (SAM)**

**SAM (Security Accounts Manager)**, Windows işletim sistemlerinde kullanıcı hesabı bilgilerini, özellikle de kullanıcı adları ve şifre hash'lerini depolayan bir veritabanı dosyasıdır. Windows, yerel kullanıcı ve grup hesaplarını yönetmek için SAM'i kullanır.

### **Önemli Noktalar:**

1. **Konum:**
    - `C:\\Windows\\System32\\config` dizininde bulunur.
2. **İşlev:**
    - SAM, kullanıcıların sisteme giriş yaparken kimlik doğrulamasını sağlar. Girilen kimlik bilgilerini veritabanındaki hash'lerle karşılaştırır.
3. **Güvenlik:**
    - SAM dosyasına erişim, kullanıcı hesap bilgilerine yetkisiz erişimi önlemek için kısıtlanmıştır. SAM, sistem tarafından korunur ve yalnızca uygun izinlere sahip işlemler tarafından erişilebilir, örneğin, Local Security Authority Subsystem Service (LSASS).
4. **Kayıt Defteri:**
    - SAM veritabanı, Windows kayıt defterinde `HKEY_LOCAL_MACHINE\\SAM` altında da temsil edilir.

SAM dosyasının güvenliği, sistemin genel güvenliği açısından kritik öneme sahiptir, çünkü kullanıcı kimlik doğrulama bilgilerini içerir.

### NTLM (NT LAN Manager)

**NTLM (NT LAN Manager)**, Microsoft'un kullanıcılar için kimlik doğrulama, bütünlük ve gizlilik sağlamayı amaçlayan bir güvenlik protokolü setidir. NTLM, çeşitli Microsoft ağ protokollerinde kimlik doğrulama amaçları için kullanılır.

### **Ana Noktalar:**

1. **Kimlik Doğrulama Protokolü:**
    - NTLM, bir istemci ile sunucu arasında kimlik doğrulama sağlamak için üç aşamalı bir el sıkışma süreci kullanan bir meydan okuma-cevap kimlik doğrulama protokolüdür. Bağlantısız ortamlarda kimlik doğrulama ve bağlantılı ortamlarda oturum güvenliği sağlamak için kullanılır.
2. **Kullanım Durumları:**
    - Kerberos'un (daha güvenli ve tercih edilen bir kimlik doğrulama protokolü) kullanılamadığı durumlarda yaygın olarak kullanılır. Bunlar:
        - Alan denetleyicisine katılmamış sistemlerde yerel girişlerin kimlik doğrulaması.
        - İş grubu ortamlarında kullanıcı kimlik doğrulaması.
        - Eski sistemler ve uygulamalarla geriye dönük uyumluluk sağlama.
3. **Güvenlik Endişeleri:**
    - NTLM, NTLMv1 ve önceki sürümlerinde kullanılan zayıf hashing algoritmaları nedeniyle çeşitli güvenlik zayıflıklarına sahiptir. Bu zayıflıklar arasında relay saldırıları, pass-the-hash saldırıları ve brute-force saldırıları bulunur. Bu nedenle, mümkün olduğunda Kerberos kullanılması ve NTLM kullanımının sınırlanması önerilir.
4. **Çalışma Mekanizması:**
    - **İstemci,** sunucuya yeteneklerini belirlemek için bir müzakere mesajı gönderir.
    - **Sunucu,** bir rastgele sayı (nonce) içeren bir meydan okuma mesajı ile yanıtlar.
    - **İstemci,** kullanıcı adını ve şifrenin nonce ile hesaplanan bir hash'ini içeren bir kimlik doğrulama mesajı ile yanıtlar.
5. **Hashing ve Şifreleme:**
    - NTLMv2, önceki sürümlere göre daha güçlü kriptografik algoritmalar (MD5 ve HMAC-MD5) kullanarak güvenliği artırır.

### Phishing (Oltalama) E-postaları

Phishing e-postaları, saldırganların kendilerini meşru varlıklar olarak gizleyerek bireyleri hassas bilgileri, örneğin kullanıcı adları, şifreler, kredi kartı numaraları ve diğer kişisel verileri ifşa etmeye ikna etmeye çalıştığı bir tür siber saldırıdır. Bu e-postalar genellikle kötü amaçlı bağlantılar veya ekler içerir ve bu da zararlı yazılımların yüklenmesine veya bilgilerin çalınmasına neden olabilir.

### **Phishing E-Posta Türleri:**

1. **Spear Phishing:**
    - **Hedeflenmiş Saldırı:** Belirli bireyler veya organizasyonlar hedef alınır.
    - **Örnek:** Güvenilir bir meslektaş veya üst düzey bir yetkiliden geldiği izlenimi veren bir e-posta, hassas bilgilerin istenmesi veya kötü amaçlı bir eyleme teşvik etme amacı taşır.
2. **Clone Phishing:**
    - **Meşru E-postanın Kopyası:** Saldırganlar, daha önce alınan meşru bir e-postanın neredeyse aynı kopyasını oluşturur, ancak kötü amaçlı bağlantılar veya ekler içerir.
    - **Örnek:** Daha önce alınan bir fatura gibi görünen ancak kötü amaçlı bir bağlantı içeren bir e-posta.
3. **Whaling:**
    - **Yüksek Değerli Hedefler:** Yüksek profilli bireyler, örneğin yöneticiler veya üst düzey yetkililer hedef alınır.
    - **Örnek:** CEO'dan geldiği izlenimi veren ve hassas şirket bilgilerini isteyen veya bir para transferini onaylayan bir e-posta.
4. **Vishing ve Smishing:**
    - **Ses ve SMS Phishing:** Sesli aramalar (vishing) veya kısa mesajlar (smishing) kullanarak kişisel bilgileri çalmaya yönelik phishing varyantları.
    - **Örnek:** Bir bankadan geldiğini iddia eden ve alıcının hesap bilgilerini doğrulamasını isteyen bir SMS.

### **Phishing E-Postaları İçin Yaygın Taktikler:**

1. **Aciliyet ve Korku:**
    - Hızlı bir eylem yapma baskısı yaratma veya korku oluşturma.
    - **Örnek:** "Hesabınız 24 saat içinde kilitlenecekse, bilgilerinizi doğrulamazsanız."
2. **Sahte Gönderici Adresleri:**
    - Meşru e-posta adreslerine benzer görünen adresler kullanma.
    - **Örnek:** [support@paypal.com](mailto:support@paypal.com) vs. [support@paipal.com](mailto:support@paipal.com).
3. **Çekici Konu Satırları:**
    - Dikkat çekici konu satırları kullanarak alıcıları e-postayı açmaya teşvik etme.
    - **Örnek:** "Acil: Fatura Vadesi Geçmiş" veya "Bir ödül kazandınız!"
4. **Kötü Amaçlı Bağlantılar ve Ekler:**
    - Kötü amaçlı bağlantılar içeren veya zararlı yazılımlar içeren ekler dahil etme.

### **Phishing E-Postalarına Karşı Savunma:**

1. **Kullanıcı Eğitim ve Eğitim:**
    - Çalışanları phishing girişimlerini tanımaya ve phishing'in tehlikelerini anlamaya yönelik düzenli eğitimler yapın.
    - Çalışanların farkındalığını ve yanıt verme yeteneklerini test etmek için simüle edilmiş phishing saldırıları gerçekleştirin.
2. **E-posta Filtreleme ve Anti-Phishing Araçları:**
    - Phishing e-postalarını tespit ve engelleyen gelişmiş e-posta filtreleme çözümleri kullanın.
    - Şüpheli web siteleri ve e-postalar hakkında kullanıcıları uyaran anti-phishing yazılımları ve tarayıcı eklentileri uygulayın.
3. **Çok Faktörlü Kimlik Doğrulama (MFA):**
    - Hassas sistemler ve bilgilere erişim için MFA gerektirerek, kimlik bilgileri ele geçirilse bile saldırganların erişim sağlamasını zorlaştırın.
4. **Güvenli E-posta Geçitleri:**
    - Gelen e-postaları phishing göstergeleri, kötü amaçlı yazılımlar ve şüpheli ekler için tarayan güvenli e-posta geçitleri kullanın.
5. **SPF, DKIM ve DMARC:**
    - E-posta sahteciliğini önlemek ve alan adınızdan gönderilen e-postaların meşru olduğunu doğrulamak için SPF, DKIM ve DMARC e-posta kimlik doğrulama protokollerini uygulayın.

### SPF, DKIM ve DMARC

1. **Sender Policy Framework (SPF)**
    - **Amaç:** Alan adı sahiplerinin, alan adlarının adına e-posta göndermeye yetkili olan e-posta sunucularını belirtmelerine olanak tanıyarak e-posta sahteciliğini önlemektir.
    - **Nasıl Çalışır:**
        - **DNS Kaydı:** Alan adı sahibi, Alan Adı Sistemi (DNS) üzerinde bir SPF kaydı yayınlar. Bu kayıt, alan adı için e-posta göndermeye yetkili IP adresleri veya ana bilgisayar adlarının bir listesidir.
        - **E-posta Doğrulama:** Bir e-posta alındığında, alıcının e-posta sunucusu gönderici alan adının SPF kaydını kontrol eder. Gönderici sunucunun IP adresi SPF kaydında listelenmişse, e-posta meşru olarak kabul edilir.
        - **Sonuç:** SPF kontrolüne dayanarak, alıcının sunucusu e-postayı kabul edebilir, reddedebilir veya şüpheli olarak işaretleyebilir.
    - **Örnek:** Bir SPF kaydı şu şekilde görünebilir:
    Bu kayıt, IP adresi 192.168.0.1 ve Google'ın e-posta sunucularına, alan adına e-posta gönderme yetkisi verir.
        
        ```
        v=spf1 ip4:192.168.0.1 include:spf.google.com -all
        
        ```
        
2. **DomainKeys Identified Mail (DKIM)**
    - **Amaç:** E-postanın bütünlüğünü ve özgünlüğünü sağlamak, alıcının e-postanın alan adı sahibi tarafından gönderildiğini ve yetkilendirildiğini doğrulamasına olanak tanımaktır.
    - **Nasıl Çalışır:**
        - **Dijital İmza:** Gönderici e-posta sunucusu, çıkıştaki e-postaları özel bir anahtar ile imzalar, e-posta başlığında benzersiz bir DKIM imzası oluşturur.
        - **DNS Kaydı:** Alan adı sahibi, DNS'de bir DKIM kaydı ile genel anahtarı yayınlar.
        - **E-posta Doğrulama:** Alıcının e-posta sunucusu, genel anahtarı DNS'den alır ve imzayı doğrulamak için kullanır. İmza eşleşirse, e-postanın değiştirilmediğini ve belirtilen alan adından gerçekten geldiğini onaylar.
        - **Sonuç:** Geçerli bir DKIM imzası, e-posta içeriğinin bozulmadığını ve meşru bir göndericiden geldiğini garanti eder.
    - **Örnek:** E-posta başlığındaki bir DKIM imzası şu şekilde görünebilir:
        
        ```
        DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject;
        bh=base64hashvalue;
        b=base64signature;
        
        ```
        
3. **Domain-based Message Authentication, Reporting, and Conformance (DMARC)**
    - **Amaç:** SPF ve DKIM kullanarak e-posta sahteciliğini tespit etmek ve önlemek için bir politika çerçevesi sağlamak. Ayrıca, kimlik doğrulama hatalarını raporlama mekanizmaları sunar.
    - **Nasıl Çalışır:**
        - **DNS Kaydı:** Alan adı sahibi, SPF veya DKIM kontrollerini geçmeyen e-postaların nasıl işleneceğini belirten bir DMARC kaydı yayınlar.
        - **Uygunluk:** DMARC, "From" adresindeki alan adının SPF ve DKIM kontrollerinde kullanılan alan adlarıyla uyumlu olmasını gerektirir.
        - **Politika Uygulaması:** DMARC politikasına göre, alıcının e-posta sunucusu kimlik doğrulama hatası yapan e-postaları nasıl ele alacağına karar verir (örneğin, reddetmek, karantinaya almak veya kabul etmek).
        - **Raporlama:** DMARC, alıcının e-posta sunucusunun kimlik doğrulama hataları hakkında alan adı sahibine rapor gönderebileceği raporlama mekanizmaları sağlar.
    - **Örnek:** Bir DMARC kaydı şu şekilde görünebilir:
        
        ```
        v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-failures@example.com; adkim=s; aspf=s
        
        ```
        

### **SPF, DKIM ve DMARC'in Kombine Kullanımı:**

SPF, DKIM ve DMARC'in birlikte kullanımı, sağlam bir e-posta kimlik doğrulama mekanizması sağlar:

1. **SPF:** E-postanın yetkili bir sunucudan gelip gelmediğini doğrular.
2. **DKIM:** E-posta içeriğinin değiştirilmediğini ve göndericinin kimliğini onaylar.
3. **DMARC:** SPF ve DKIM kontrollerini geçmeyen e-postalar için politika uygular ve alan adı sahibine geri bildirim sağlar.

### **E-posta Phishing Tespiti için Saldırgan Teknikleri:**

- **1-Yeni Oluşturulmuş Alan Adı.**
- **2-Kara listeye alınmamış SMTP sunucularının kullanılması.**
- **3-Eğer mağdur, e-postayı açmadan önce bir Sandbox kullanıyorsa, saldırgan Sandbox kaçınma teknikleri kullanır.**

### **Phishing E-postalarını Tanımlama:**

1. **Göndericinin E-posta Adresini Kontrol Edin:**
    - İnce yazım hataları veya alışılmadık alan adlarını arayın.
2. **Bağlantılara Üzerinde Bekleyin:**
    - Bağlantılar üzerinde tıklamadan bekleyin ve gerçek URL'yi görün. URL'nin meşru bir siteye yönlendirdiğinden emin olun.
3. **Kötü Dil Bilgisi ve Yazım Hatalarını Arayın:**
    - Pek çok phishing e-postasında belirgin dil bilgisi ve yazım hataları bulunur.
4. **Acil Durum ve Olağandışı Taleplere Dikkat Edin:**
    - Aciliyet yaratan veya hassas bilgileri talep eden e-postalara şüpheyle yaklaşın.
5. **Kaynağı Doğrulayın:**
    - Şüphedeyseniz, e-postanın doğruluğunu teyit etmek için bilinen, meşru bir iletişim kanalı aracılığıyla göndericiyle doğrudan iletişime geçin.

### **E-posta Soruşturması Sırasında Toplanacak Bilgiler:**

- Gönderici e-posta adresi
- Gönderici IP adresi
- E-posta konu satırı
- Alıcı e-posta adresi
- Yanıtla e-posta adresi (varsa)
- Tarih / saat
- Herhangi bir URL bağlantısı (URL kısaltıcı servisi kullanıldıysa, gerçek URL bağlantısını almak gerekir)
- Ek dosyasının adı
- Ek dosyasının hash değeri (hash türü MD5 veya SHA256)

### E-posta Akışı

1. **Oluşturma → Göndericinin E-posta İstemcisi (MUA - Mail User Agent):**
    - **Eylem:** Bir e-posta istemcisi (örneğin, Outlook, Gmail, Thunderbird) kullanarak e-posta oluşturulur.
    - **Bileşenler:** E-posta göndericinin adresini, alıcının adresini, konu başlığını, gövdesini ve ekleri içerir.
2. **Gönderim → E-posta Gönderim Ajanı (MSA):**
    - **Eylem:** E-posta istemcisi e-postayı MSA'ya iletir.
    - **Port:** Genellikle güvenli gönderim için port 587 veya 465 kullanılır.
3. **İşleme → E-posta Aktarım Ajanı (MTA):**
    - **Eylem:** MSA, e-postayı MTA'ya teslim eder; MTA e-postayı varış noktasına yönlendirmekle sorumludur.
    - **DNS Sorgulama:** MTA, alıcının alan adının MX (Mail Exchange) kayıtlarını sorgulayarak alıcının e-posta sunucusunu bulur.
4. **Teslimat → Alıcının E-posta Sunucusu (MX Sunucusu):**
    - **Eylem:** Son MTA, e-postayı MX kayıtları tarafından tanımlanan alıcının e-posta sunucusuna teslim eder.
    - **Güvenlik Kontrolleri:** Alıcının e-posta sunucusu SPF, DKIM ve DMARC doğrulamaları, spam filtreleme ve kötü amaçlı yazılım taraması gibi çeşitli güvenlik kontrolleri gerçekleştirebilir.
5. **Teslim Alma → E-posta Teslimat Ajanı (MDA):**
    - **Eylem:** MDA, e-postayı alıcının e-posta sunucusundan alır ve e-postayı alıcının posta kutusunda saklar.
6. **Erişim → Alıcının E-posta İstemcisi (MUA):**
    - **Protokoller:** E-posta istemcisi, IMAP (Internet Message Access Protocol) veya POP3 (Post Office Protocol) gibi protokolleri kullanarak e-postaları e-posta sunucusundan alır.
        - **IMAP (Port 143/993):** E-posta istemcisinin e-posta sunucusunda saklanan e-postalara erişmesini ve bunları yönetmesini sağlar.
        - **POP3 (Port 110/995):** E-postayı e-posta sunucusundan istemciye indirir ve genellikle sunucudan siler.

### Kötü Amaçlı Davranışları Gösteren Etkinlikler

1. **Ağ Aktivitesi**
    - **Sıradışı Trafik Desenleri:**
        - Dış IP adreslerine büyük veri transferleri.
        - Özellikle standart olmayan portlarda alışılmadık etkinlik.
    - **Bilinen Kötü Amaçlı IP'lere Bağlantılar:**
        - Kötü amaçlı yazılım, botnetler veya siber suçlarla ilişkili IP adresleriyle iletişim.
    - **Yanal Hareket:**
        - İç ağ taraması.
        - Bir iç sistemden diğerine alışılmadık erişim girişimleri.
        - PsExec, PowerShell veya WMI gibi yönetim araçlarının ağ içinde hareket için kullanılması.
2. **Kullanıcı Davranışı**
    - **Sıradışı Giriş Desenleri:**
        - Birden fazla başarısız giriş girişimi.
        - Tanımadık yerlerden veya IP adreslerinden girişler.
    - **Erişim Anomalileri:**
        - Kullanıcının genellikle kullanmadığı hassas verilere veya sistemlere erişim.
        - Kısa bir süre içinde farklı yerlerden birden fazla giriş.
3. **Uç Nokta Aktivitesi**
    - **Süreç Anomalileri:**
        - Alışılmadık süreçlerin veya uygulamaların çalıştırılması.
        - Sistem yardımcı programlarının (örneğin, PowerShell, Komut İstemi) yetkisiz veya beklenmedik kullanımı.
    - **Dosya Aktivitesi:**
        - Sistem dosyalarının oluşturulması veya değiştirilmesi.
        - Sistem dizinlerinde yeni veya bilinmeyen dosyaların varlığı.
        - Büyük sayıda dosyanın şifrelenmesi (fidye yazılımının göstergesi).
    - **Kayıt Değişiklikleri:**
        - Windows kayıt defterinde yetkisiz değişiklikler, genellikle kalıcılığı sağlamak için kullanılır.
4. **Uygulama Aktivitesi**
    - **Anomalik Uygulama Davranışı:**
        - Uygulamaların sık sık çökmesi veya beklenmedik şekilde davranması.
        - Uygulamaların gerekçe olmaksızın dış sistemlerle bağlantı kurma girişimleri.
    - **Şüpheli Betikler veya Makrolar:**
        - E-posta eklerinden gelen belgelerde betiklerin veya makroların çalıştırılması.
        - Açık bir neden olmadan PowerShell betiklerinin çalıştırılması.
5. **E-posta Aktivitesi**
    - **Phishing Göstergeleri:**
        - Bilinmeyen veya şüpheli göndericilerden gelen bağlantılar veya ekler.
        - Meşru adreslere benzeyen sahte e-posta adresleri.
    - **Sıradışı Gönderim Desenleri:**
        - Kısa bir süre içinde yüksek hacimli çıkış e-postaları.
        - Beklenmedik veya alışılmadık alıcılara gönderilen e-postalar.
6. **Sistem ve Uygulama Günlükleri**
    - **Günlük Anomalileri:**
        - Günlüklerde açıklanamayan boşluklar veya silmeler.
    - **Yetki Yükseltme Girişimleri:**
        - Sistem yapılandırmalarını veya güvenlik ayarlarını değiştirme girişimleri.
        - Yönetici hesaplarına veya güvenlik araçlarına yetkisiz erişim.
7. **Dış Göstergeler**
    - **Tehdit İstihbarat Beslemeleri:**
        - Organizasyon hedefli yeni güvenlik açıkları, tehditler veya aktif saldırılar hakkında tehdit istihbarat kaynaklarından gelen uyarılar.
    - **Kompromize Olmuş Hesaplar:**
        - Karanlık ağda rapor edilen hesaplar veya kimlik bilgilerinin ihlali.

### Savunma Önlemleri ve Tespit Stratejileri

1. **Ağ İzleme:**
    - Ağ saldırı tespit ve önleme sistemleri (IDS/IPS) uygulayın.
    - Günlük verilerini toplamak ve analiz etmek için güvenlik bilgi ve olay yönetimi (SIEM) sistemlerini kullanın.
2. **Kullanıcı ve Varlık Davranış Analitiği (UEBA):**
    - Kullanıcı davranış desenlerinde anomalileri tespit etmek için UEBA araçlarını kullanın.
    - Sıradışı giriş girişimleri, yetki yükseltme ve veri erişimi için uyarılar ayarlayın.
3. **Uç Nokta Tespit ve Yanıt (EDR):**
    - Şüpheli uç nokta etkinliklerini izlemek ve yanıt vermek için EDR çözümleri dağıtın.
    - Antivirüs ve anti-kötü amaçlı yazılım araçlarını düzenli olarak güncelleyin.
4. **Erişim Kontrolleri ve Politikalar:**
    - Kullanıcı hesapları ve erişim kontrolleri için en az ayrıcalık ilkesini (PoLP) uygulayın.
    - Kritik sistemlere erişimi güvence altına almak için çok faktörlü kimlik doğrulama (MFA) uygulayın.
5. **E-posta Güvenliği:**
    - Phishing ve kötü amaçlı e-postaları engellemek için e-posta filtreleme çözümleri kullanın.
    - Kullanıcıları phishing girişimlerini ve şüpheli e-postaları tanıma konusunda eğitin.
6. **Düzenli Denetimler ve Penetrasyon Testleri:**
    - Düzenli güvenlik denetimleri ve zayıflık değerlendirmeleri gerçekleştirin.
    - Potansiyel zayıflıkları belirlemek ve azaltmak için penetrasyon testleri yapın.

### NetBIOS

- **Tanım:** NetBIOS (Ağ Temel Girdi/Çıktı Sistemi), yerel alan ağında (LAN) cihazlar arasında iletişim için kullanılan bir ağ protokolüdür.
- **Fonksiyonlar:** NetBIOS, OSI modelinin oturum katmanıyla ilgili hizmetler sunar; bunlar arasında ad çözümleme (NetBIOS Ad Servisi - NBNS), oturum kurulumu ve veri transferi bulunur.
- **Kalıntı Protokol:** IBM tarafından geliştirilen NetBIOS, özellikle Microsoft Windows ortamlarında LAN iletişimi için bir standart haline gelmiştir.
- **Kullanım:** Modern TCP/IP protokollerinin büyük ölçüde yerini almasına rağmen, bazı eski sistemler ve uygulamalarda hala kullanılmaktadır.
- **Portlar:**
    - 137 (NetBIOS Ad Servisi)
    - 138 (NetBIOS Datagram Servisi)
    - 

139 (NetBIOS Oturum Servisi)

### SMB

- **Tanım:** SMB (Sunucu Mesaj Bloğu), bir ağ üzerinde uygulamaların dosyalara erişmesini ve yazmasını sağlar ve sunucu programlarından hizmet talep eder.
- **Fonksiyonlar:** OSI modelinin uygulama katmanında çalışır ve dosya, yazıcı, seri portlar ve çeşitli ağ iletişimleri arasında paylaşılan erişimi sağlar.
- **Sürümler:** SMB zamanla çeşitli sürümlere (SMB1, SMB2, SMB3) evrim geçirmiştir; her biri performans, güvenlik özellikleri ve yetenekleri iyileştirmiştir.
- **Güvenlik Endişeleri:** Özellikle SMB1 sürümü, WannaCry fidye yazılımı gibi bilinen güvenlik açıklarına sahip olduğundan, organizasyonların daha yeni sürümlere geçmeleri veya SMB1'i devre dışı bırakmaları önerilmektedir.

### Dijital Sertifikalar

- **Tanım:** Dijital sertifika, bir genel anahtarın sahipliğini kanıtlamak için kullanılan elektronik bir belgedir. Anahtarın bilgilerini, sahibinin kimliğini ve sertifikanın içeriğini doğrulayan bir varlığın dijital imzasını içerir.
- **Verilme:** Sertifikalar genellikle bir sertifika yetkilisi (CA) tarafından verilir; CA, sertifika sahibinin kimliğini doğrulayan güvenilir bir üçüncü tarafa işaret eder.
- **Bileşenler:**
    - Sertifika Sahibinin Genel Anahtarı
    - Sertifika Sahibinin Kimliği (örneğin, ad, e-posta adresi)
    - Verici (CA) Bilgileri
    - Vericinin Dijital İmzası
    - Geçerlilik Süresi (başlangıç ve bitiş tarihler)
- **Kullanım:**
    - **SSL/TLS:** Web sitelerini güvence altına alma ve internet üzerinden iletilen verileri şifreleme.
    - **Kod İmzalama:** Yazılımın kaynağını doğrulama ve değişmediğini sağlama.
    - **E-posta Güvenliği:** E-postaları şifreleme ve dijital olarak imzalama, gönderici kimliğini doğrulama ve mesaj bütünlüğünü koruma.

### Kimlik Doğrulama: Ağ ve Sistemlere Güvenli Erişim Sağlama

**Kimlik Doğrulama (Authentication):**

- Kimlik doğrulama, kullanıcıların veya sistemlerin kimliklerini doğrulamak ve güvenli erişim sağlamak için kullanılan bir süreçtir. VPN'ler, Wi-Fi ağları gibi çeşitli ağ hizmetlerinde uygulanır.
- **Yöntemler:**
    - **Parolalar:** Kullanıcıların kişisel bilgilerini doğrulamak için.
    - **Biyometrik Veriler:** Parmak izi, retina taraması gibi fiziksel özellikler.
    - **Çok Faktörlü Kimlik Doğrulama (MFA):** Birden fazla kimlik doğrulama yöntemi kullanarak güvenliği artırır.

---

### SIEM Çözümleri

**SIEM (Güvenlik Bilgi ve Olay Yönetimi - Security Information and Event Management):**

- SIEM çözümleri, güvenlik olaylarını ve günlük verilerini merkezi bir düğümde analiz eder, olay korelasyonu ve tehdit izleme gerçekleştirir (Olay Yönetimi).
- Farklı cihazlardan veya kaynaklardan gelen günlük verilerini indeksler ve ayrıştırır, analiz eder ve raporlar (Bilgi Yönetimi).

**Ana Bileşenler ve İşlevler:**

1. **Veri Toplama:**
    - **Günlük Yönetimi:** Ağaç cihazlar, sunucular, uygulamalar, veritabanları ve uç noktalar gibi çeşitli kaynaklardan gelen günlükleri toplar ve saklar.
    - **Olay Korelasyonu:** Güvenlik olaylarını toplar ve korelasyon sağlar, desenleri ve potansiyel tehditleri belirler.
2. **Normalizasyon ve Ayrıştırma:**
    - Ham olay verilerini standart bir formata dönüştürür, böylece analiz ve korelasyon daha kolay hale gelir.
3. **Uyarı ve İzleme:**
    - **Gerçek Zamanlı İzleme:** Gelen olayları gerçek zamanlı olarak izler, güvenlik olaylarını tespit eder.
    - **Uyarı:** Önceden tanımlanmış kurallar ve eşikler temelinde şüpheli etkinlikler veya potansiyel güvenlik ihlalleri için uyarılar ve bildirimler oluşturur.
4. **Olay Tespiti ve Yanıt:**
    - **Tehdit Tespiti:** Bilgi analitiği, makine öğrenimi ve tehdit istihbaratı kullanarak bilinen ve bilinmeyen tehditleri tespit eder.
    - **Olay Yanıtı:** Güvenlik olaylarını araştırmak ve hızlı bir şekilde yanıt vermek için iş akışları ve araçlar sunar.
5. **Adli Analiz ve Araştırma:**
    - Güvenlik ekiplerinin güvenlik olayları ve ihlallerinin detaylı adli analizini yapmalarını sağlar.
6. **Uyum Raporlaması:**
    - Regülasyon gereksinimlerine uyumu destekler, denetim raporları üretir ve güvenlik kontrolleri ile faaliyetlerinin kanıtlarını sağlar.
7. **Kullanıcı ve Varlık Davranış Analitiği (UEBA):**
    - Kullanıcı davranışlarını ve varlık aktivitelerini analiz eder, anormallikleri ve iç tehditleri tespit eder.
    - Kompromize olmuş hesapları veya kötü niyetli iç faaliyetleri tanımlar.

**SIEM Çözümlerinin Faydaları:**

- **Merkezi Görünürlük:** Organizasyonun güvenlik duruşunu ve olaylarını merkezi bir bakış açısıyla sağlar.
- **Erken Tehdit Tespiti:** Güvenlik olaylarını ve tehditleri erken tespit etmeye yardımcı olur, büyük zararlara yol açmadan.
- **Yanıt Verimliliği:** Uyarı, araştırma ve iyileştirme süreçlerini otomatikleştirerek olay yanıt sürelerini iyileştirir.
- **Uyum Desteği:** Sürekli izleme ve raporlama yoluyla regülasyon gereksinimlerini karşılamayı kolaylaştırır.
- **Operasyonel Verimlilik:** Manuel çabaları azaltarak ve otomasyon yoluyla verimliliği artırarak güvenlik operasyonlarını düzene sokar.

**Zorluklar:**

- **Karmaşıklık:** SIEM çözümlerinin uygulanması ve yönetimi karmaşık ve kaynak yoğun olabilir.
- **Ayarlama ve Yanlış Pozitifler:** Yanlış pozitifleri azaltmak ve doğru tehdit tespiti sağlamak için ayar gerektirir.
- **Yetenek Gereksinimleri:** SIEM verilerini etkili bir şekilde yapılandırmak, işletmek ve yorumlamak için yetenekli güvenlik personeli gerektirir.

**Sonuç:**
SIEM çözümleri, modern siber güvenlik stratejilerinde proaktif tehdit tespiti, olay yanıt yetenekleri ve uyum desteği sağlayarak kritik bir rol oynar. Organizasyonların güvenlik olaylarını gerçek zamanlı olarak izlemelerini, analiz etmelerini ve yanıt vermelerini sağlar, böylece genel güvenlik duruşunu ve siber tehditlere karşı dayanıklılığını artırır.

---

### Tanımlar

1. **Gizlilik (Confidentiality):** Hassas bilgilere yalnızca yetkili kişilerin erişimini sağlamak. Şifreleme, erişim kontrolleri ve veri sınıflandırması ile sağlanır.
2. **Bütünlük (Integrity):** Verilerin doğruluğunu ve güvenilirliğini korumak. Veri doğrulama, kontrol toplamları ve sürüm kontrolü gibi önlemlerle yetkisiz değişiklikler önlenir.
3. **Erişilebilirlik (Availability):** Bilgi ve kaynakların gerektiğinde erişilebilir olmasını sağlamak. Yedeklilik, yedekleme sistemleri ve felaket kurtarma planları bu konuda yardımcı olur.
4. **Kimlik Doğrulama (Authentication):** Kullanıcıların ve sistemlerin kimliklerini doğrulama. Parolalar, biyometrikler ve çok faktörlü kimlik doğrulama kullanılarak gerçekleştirilir.
5. **Yetkilendirme (Authorization):** Yetkili kullanıcılara uygun erişim seviyelerinin verilmesi. Erişim kontrol listeleri, rol tabanlı erişim kontrolü (RBAC) ve en az ayrıcalık ilkeleri ile uygulanır.
6. **Risk Yönetimi (Risk Management):** Potansiyel riskleri ve güvenlik açıklarını tanımlama, etki değerlendirmesi yapma ve bu riskleri hafifletmek veya yönetmek için önlemler uygulama.
7. **Güvenlik Farkındalığı ve Eğitim (Security Awareness and Training):** Çalışanları ve kullanıcıları güvenlik en iyi uygulamaları ve potansiyel tehditler hakkında eğitme, farkındalığı artırma ve sorumlu davranışı teşvik etme.
8. **Zafiyet Yönetimi (Vulnerability Management):** Sistemleri düzenli olarak tarama ve değerlendirme, güvenlik açıklarını gidermek için yamalar veya güncellemeler uygulama.
9. **Saldırı Tespit ve Önleme (Intrusion Detection and Prevention):** Ağ veya sistem içinde yetkisiz erişim veya kötü niyetli etkinlikleri tespit ve önlemek için araçlar ve sistemler kullanma.
10. **Güvenlik Politikaları ve Prosedürleri (Security Policies and Procedures):** Bilgilerin nasıl işleneceğini, paylaşılacağını ve korunacağını düzenleyen açık güvenlik politikaları, yönergeler ve prosedürler oluşturma.
11. **Olay Yanıtı (Incident Response):** Güvenlik olaylarına yanıt vermek için bir plan geliştirme, bu plan içinde olayları sınırlama, araştırma ve kurtarma işlemleri yapma.
12. **Fiziksel Güvenlik (Physical Security):** Sunucular, veri merkezleri ve ağ ekipmanları gibi fiziksel varlıkları yetkisiz erişimden koruma.
13. **Kriptografi (Cryptography):** Veriyi hem iletimde hem de dinlenme halinde şifreleme teknikleri kullanarak güvence altına alma.
14. **Ağ Güvenliği (Network Security):** Ağları dış tehditlerden korumak için güvenlik duvarları, saldırı tespit sistemleri ve diğer önlemler uygulama.
15. **Uygulama Güvenliği (Application Security):** Yazılım uygulamalarının güvenlik göz önünde bulundurularak geliştirilmesi, test edilmesi ve sürdürülmesini sağlama.
16. **Güven Amaçlı Doğrulama (Trust but Verify):** Bir varlığı veya sistem davranışını güvenilir bulsak bile her zaman doğrulama yapmalıyız.
17. **Sıfır Güven (Zero Trust):** “Asla güvenme, her zaman doğrula” prensibini takip eder.

### Yaygın Güvenlik Açıkları

1. **Yamanmamış Yazılımlar:** Yazılımların düzenli olarak güncellenmemesi ve yamaların uygulanmaması, saldırganların kullanabileceği güvenlik açıkları bırakabilir. Saldırganlar genellikle yamaları yayınlanmış bilinen güvenlik açıklarını hedef alır.
2. **Zayıf Şifreler:** Kolay tahmin edilebilen veya varsayılan şifrelerin kullanılması, saldırganların sistemlere ve hesaplara yetkisiz erişim sağlamasına yol açabilir.
3. **Şifreleme Eksikliği:** Hassas verilerin şifrelenmemesi, verilerin yetkisiz erişimlere karşı korunmasını zorlaştırır.
4. **SQL Injection:** Web uygulamalarında yetersiz doğrulanan girişler, saldırganların kötü niyetli SQL kodları enjekte etmelerine ve bu şekilde veritabanlarına yetkisiz erişim sağlamalarına neden olabilir.
5. **Cross-Site Scripting (XSS):** Web uygulamalarında yetersiz giriş doğrulama, saldırganların diğer kullanıcıların görüntülediği web sayfalarına kötü niyetli betikler enjekte etmelerine olanak tanır, bu da kullanıcı bilgilerini çalabilir veya oturumlarını tehlikeye atabilir.
6. **Phishing (Oltalama):** Çalışanların oltalama e-postalarına düşmesi, kimlik bilgisi çalınmasına veya kötü amaçlı yazılım enfeksiyonuna yol açabilir.
7. **İç Tehditler:** Kötü niyetli veya yetersiz güvenlik eğitimi almış çalışanlar ya da yükleniciler, erişim ayrıcalıklarını kötüye kullanabilirler.
8. **Sosyal Mühendislik:** Saldırganlar, bireyleri gizli bilgileri açıklamaya veya güvenliği tehlikeye atan eylemler gerçekleştirmeye manipüle edebilirler.
9. **Uzaktan Çalışma Riskleri:** Yeterince güvence altına alınmamış uzaktan çalışma ortamları, yetkisiz erişim, veri sızıntısı ve diğer güvenlik ihlallerine yol açabilir.

---

### Yaygın Saldırı Türleri İçin Olay Yanıtı

1. **Brute Forcing (Kaba Kuvvet Saldırısı)**
    - **Ayrıntılar:** Saldırgan, bir şifreyi tahmin etmek için birçok farklı şifre denemesi yapar.
    - **Tehdit Göstergeleri:** Kısa bir süre içinde birçok giriş başarısızlığı.
    - **Nerede Araştırmalı:**
        - Aktif dizin günlükleri, Uygulama günlükleri, Operasyonel sistem günlükleri, Kullanıcı ile iletişim.
    - **Olası Eylemler:**
        - Eğer geçerli değilse: Hesabı devre dışı bırakın ve saldırganı araştırın/engelleyin.
2. **Botnetler**
    - **Ayrıntılar:** Saldırganlar, hedef sunucuyu DDoS saldırıları veya diğer kötü amaçlı etkinlikler için kullanır.
    - **Tehdit Göstergeleri:**
        - Şüpheli IP'lere bağlantılar.
        - Anormal yüksek ağ trafiği.
    - **Nerede Araştırmalı:**
        - Ağ trafiği, OS günlükleri (yeni süreçler), Sunucu sahibi ile iletişim, Destek ekibi ile iletişim.
    - **Olası Eylemler:**
        - Onaylandıysa:
            - Sunucuyu izole edin.
            - Kötü niyetli süreçleri kaldırın.
            - Enfeksiyona neden olan güvenlik açığını yamalayın.
3. **Ransomware (Fidye Yazılımı)**
    - **Ayrıntılar:** Dosyaları şifreleyen ve dosyaların şifresini çözmek için kullanıcıdan fidye (para ödemesi) talep eden bir kötü amaçlı yazılım türüdür.
    - **Tehdit Göstergeleri:**
        - Antivirüs uyarıları.
        - Şüpheli IP'lere bağlantılar.
    - **Nerede Araştırmalı:**
        - AV günlükleri, OS günlükleri, Hesap günlükleri, Ağ trafiği.
    - **Olası Eylemler:**
        - AV taramaları talep edin.
        - Makineyi izole edin.
4. **Veri Sızdırma (Data Exfiltration)**
    - **Ayrıntılar:** Saldırgan (veya kötü niyetli çalışan), verileri harici kaynaklara sızdırır.
    - **Tehdit Göstergeleri:**
        - Anormal yüksek ağ trafiği.
        - Bulut depolama çözümlerine (Dropbox, Google Cloud) bağlantılar.
    - **Nerede Araştırmalı:**
        - Ağ trafiği, Proxy günlükleri, OS günlükleri.
    - **Olası Eylemler:**
        - Eğer çalışan ise: Yöneticiyi bilgilendirin, tam adli analiz yapın.
        - Eğer dış tehdit ise: Makineyi izole edin, ağdan ayırın.
5. **Gelişmiş Kalıcı Tehditler (APTs)**
    - **Ayrıntılar:** Saldırganlar sisteme erişim sağlar ve daha fazla istismar için arka kapılar oluşturur. Genellikle tespiti zordur.
    - **Tehdit Göstergeleri:**
        - Şüpheli IP'lere bağlantılar veya anormal yüksek ağ trafiği veya mesai saatleri dışındaki erişim günlükleri veya yeni yönetici hesapları oluşturma.
    - **Nerede Araştırmalı:**
        - Ağ trafiği, Erişim günlükleri, OS günlükleri (yeni süreçler, yeni bağlantılar, anormal kullanıcılar), Sunucu sahibi/destek ekipleri ile iletişim.
    - **Olası Eylemler:** Makineyi izole edin ve resmi adli analiz sürecine başlayın.

### OSI Katman Saldırıları

1. **Fiziksel Katman**
2. **Veri Bağlantı Katmanı**
    - **ARP Spoofing/Poisoning (ARP Sahteciliği/Zehirleme):** ARP (Address Resolution Protocol) tablosunu hedef alarak yanlış IP-MAC eşleşmeleri oluşturma.
    - **MAC Flooding (MAC Taşması):** Ağa çok sayıda MAC adresi göndererek ağ cihazlarını aşırı yükleme.
3. **Ağ Katmanı**
    - **IP Spoofing (IP Sahteciliği):** Sahte IP adresleri kullanarak kimliğini gizleme ve yetkisiz erişim sağlama.
    - **IPv6 Tunneling (IPv6 Tünelleme):** IPv6 trafiğini IPv4 ağlarında gizlemek için tünel oluşturma.
    - **Smurf Attack (Smurf Saldırısı):** ICMP (Internet Control Message Protocol) trafiğini hedef alarak ağ trafiğini aşırı yükleme.
    - **ICMP Flooding (ICMP Taşması):** Hedef ağ cihazlarını aşırı miktarda ICMP paketleri ile boğma.
    - **DHCP Spoofing (DHCP Sahteciliği):** Sahte DHCP sunucuları oluşturarak ağ üzerindeki cihazlara yanlış IP adresleri verme.
    - **DHCP Starvation (DHCP Açlığı):** DHCP sunucusunun IP havuzunu tüketerek yeni cihazların IP almasını engelleme.
4. **Taşıma Katmanı**
    - **TCP SYN Flood (TCP SYN Taşması):** Sunucunun kaynaklarını tüketmek için birçok SYN paketi gönderme.
    - **TCP Session Hijacking (TCP Oturum Ele Geçirme):** Aktif TCP oturumlarını ele geçirme ve kontrol etme.
    - **TCP Reset Attack (TCP Sıfırlama Saldırısı):** TCP bağlantılarını kesmek için TCP sıfırlama (RST) paketleri gönderme.
    - **UDP Flooding (UDP Taşması):** Hedefe büyük miktarda UDP paketi göndererek trafiği boğma.
5. **Oturum Katmanı**
    - **Session Hijacking (Oturum Ele Geçirme):** Aktif oturumları ele geçirme ve yetkisiz erişim sağlama.
6. **Sunum Katmanı**
    - **SSL → TLS Striping:** SSL/TLS şifrelemesinin devre dışı bırakılması ve veri iletiminin şifresiz hale getirilmesi.
7. **Uygulama Katmanı**
    - **DNS**
        - **Zone Transfer (Alan Transferi):** DNS veritabanlarının kopyalanması.
        - **DNS Spoofing (DNS Sahteciliği):** Yanlış DNS yanıtları göndererek trafik yönlendirmesi yapma.
    - **HTTP/HTTPS**
        - **Web Saldırıları:** Web uygulamalarına yönelik çeşitli saldırılar.
    - **FTP (Düz Metin Protokolü)**
        - **Brute Force (Kaba Kuvvet):** FTP hesaplarına şifre tahmin saldırıları düzenleme.
        - **Critical Files Download (Kritik Dosyaları İndirme):** Önemli dosyaları indirme.
        - **Malicious Files Upload (Kötü Niyetli Dosyalar Yükleme):** Kötü amaçlı dosyaları yükleme.
    - **TELNET**
        - **Brute Force (Kaba Kuvvet):** Telnet hesaplarına şifre tahmin saldırıları düzenleme.

### Kimlik ve Erişim Yönetimi (IAM)

- **IAM**: Yalnızca yetkili kullanıcıların belirli kaynaklara ve verilere erişimini sağlayan ve bu erişimi izleyen ve kontrol eden bir çerçevedir. IAM sistemleri, erişimi yönetmek için rol tabanlı erişim kontrolü, çok faktörlü kimlik doğrulama ve tek oturum açma gibi çeşitli teknolojiler kullanır. IAM sistemleri, HIPAA, GDPR gibi düzenleyici gereksinimlerle uyum sağlamaya yardımcı olur.

### Tespit Kategorileri

1. **Gerçek Pozitif:** Bir saldırının varlığını doğru şekilde tespit eden bir uyarıdır.
2. **Gerçek Negatif:** Kötü niyetli etkinlik olmadığında ve uyarı tetiklenmediğinde.
3. **Yanlış Pozitif:** Bir tehdidin varlığını yanlış bir şekilde tespit eden bir uyarıdır. Bu, bir IDS'nin faaliyetleri kötü niyetli olarak tanımladığı, ancak gerçekte böyle olmadığı durumlarda ortaya çıkar. Yanlış pozitifler, güvenlik ekiplerinin geçerli olmayan uyarıları araştırmak için zaman ve kaynak harcamasına neden olur.
4. **Yanlış Negatif:** Bir tehdidin varlığının tespit edilmediği durumdur. Bu, kötü niyetli bir etkinlik meydana geldiğinde ancak IDS'nin bunu tespit edemediği durumlarda ortaya çıkar. Yanlış negatifler, güvenlik ekiplerinin karşı karşıya olduğu gerçek saldırıları fark etmemesi nedeniyle tehlikeli olabilir.

### Saldırı Yüzeyi

- **Saldırı yüzeyi**, bir tehdit aktörünün istismar edebileceği tüm potansiyel güvenlik açıklarıdır.

### HTTPS Nasıl Çalışır

HTTPS (Hypertext Transfer Protocol Secure), internet üzerinde güvenli iletişim için kullanılan bir protokoldür. HTTPS'nin nasıl çalıştığı basit bir şekilde şu şekildedir:

1. **Şifreleme:** HTTPS, istemci (örneğin, bir web tarayıcısı) ile sunucu (örneğin, bir web sitesi) arasında iletilen verileri güvence altına almak için şifreleme kullanır.
2. **SSL/TLS Protokolü:** HTTPS, şifreli bir bağlantı kurmak için SSL (Secure Sockets Layer) veya daha yaygın olarak TLS (Transport Layer Security) protokollerine dayanır.
3. **Eller Sıkışma Süreci:**
    - **Client Hello:** Süreç, bir istemci (örneğin, bir web tarayıcısı) "Client Hello" mesajını sunucuya gönderdiğinde başlar. Bu mesaj, güvenli bir bağlantı kurma niyetini belirtir ve desteklenen SSL/TLS sürümleri, şifreleme algoritmaları ve diğer parametreleri sunar.
    - **Server Hello:** Sunucu, istemcinin listesinde en iyi SSL/TLS sürümünü ve şifreleme algoritmasını seçen ve dijital sertifikasını gönderen "Server Hello" mesajını yanıtlar.
    - **Sertifika Doğrulama:** İstemci, sunucunun dijital sertifikasını doğrular ve sertifikanın geçerli ve güvenilir bir Sertifika Yetkilisi (CA) tarafından verilmiş olduğunu teyit eder. Bu sertifika, sunucunun genel anahtarını içerir.
    - **Anahtar Değişimi:** Asimetrik şifreleme (genel anahtar şifreleme) kullanılarak, istemci ve sunucu, simetrik şifreleme (paylaşılan gizli anahtar) için güvenli bir oturum anahtarı oluşturmak üzere kriptografik anahtarları değiştirir.
4. **Güvenli Veri Transferi:**
    - Güvenli bağlantı kurulduktan sonra, istemci ile sunucu arasında iletilen tüm veriler simetrik oturum anahtarı kullanılarak şifrelenir.
    - Bu şifreleme, verilerin yetkisiz bir tarafça yakalanmış olsa bile kolayca çözülemeyeceğini garanti eder.
5. **Kimlik Doğrulama ve Bütünlük:**
    - HTTPS, kimlik doğrulama ve veri bütünlüğü sağlar. Sunucunun dijital sertifikası, istemcinin hedeflenen sunucuya bağlandığını ve bir sahtekar (man-in-the-middle saldırısı) olmadığını garanti eder.
    - Mesaj bütünlüğü, iletim sırasında verilerin değiştirilmediğini veya müdahale edilmediğini sağlamak için kriptografik hash fonksiyonları aracılığıyla korunur.
6. **Performans Dikkate Alınmaları:**
    - HTTPS, şifreleme ve şifre çözme süreçleri nedeniyle ek yük getirir, ancak modern donanım ve optimize edilmiş protokoller (TLS 1.3 gibi) performans etkilerini en aza indirir ve HTTPS'nin webde yaygın olarak benimsenmesini sağlar.
7. **Uçtan Uca Güvenlik:**
    - HTTPS yalnızca web sayfalarını değil, aynı zamanda HTTP üzerinden değiştirilen diğer verileri de güvence altına alır, örneğin API istekleri, form gönderimleri ve dosya indirmeleri.

### EDR (Uç Nokta Tespiti ve Yanıt)

- **Odak:** EDR, uç nokta seviyesinde güvenlik tehditlerini izleme ve yanıt verme konusunda odaklanır, örneğin bireysel cihazlar (bilgisayarlar, sunucular, mobil cihazlar).
- **Yetenekler:**
    - **Uç Nokta Görünürlüğü:** İşlem yürütmeleri, dosya erişimleri, ağ bağlantıları ve kayıt defteri değişiklikleri dahil olmak üzere uç nokta etkinliklerine derinlemesine görünürlük sağlar.
    - **Tehdit Tespiti:** Davranış

sal analizler, makine öğrenimi ve imza tabanlı tespit kullanarak uç noktalardaki şüpheli etkinlikleri ve potansiyel tehditleri belirler.

- **Olay Yanıtı:** Güvenlik ekiplerinin tehditleri sınırlamasına ve hafifletmesine olanak tanıyan hızlı araştırma ve yanıt süreçlerini kolaylaştırır.
- **Adli Analiz:** Güvenlik olayları sırasında olayların zaman çizelgesini yeniden oluşturmak için uç nokta verilerini toplar ve analiz eder.
- **Uç Nokta İzolasyonu:** Tehditlerin daha fazla yayılmasını önlemek için tehlikeye atılmış uç noktaları ağdan izole etme yeteneğine sahiptir.
- **Faydalar:**
    - Uç noktalar üzerindeki görünürlük ve kontrolü artırır, özellikle dağılmış ve uzaktan çalışma ortamlarında, ve uç nokta tabanlı tehditlere hızlı tespit ve yanıt sağlar, bu da tespit edilmeyen süreyi (saldırganların fark edilmeden kaldığı süre) azaltır.

### XDR (Genişletilmiş Tespit ve Yanıt)

- **Kapsam:** XDR, uç noktaların ötesine geçer ve uç noktalar, ağlar, e-posta ve bulut ortamları dahil olmak üzere birden fazla güvenlik katmanından veri toplar ve ilişkilendirir.
- **Entegrasyon:**
    - **Veri Kaynakları:** EDR, NDR, e-posta güvenliği ve bulut güvenliği platformları gibi çeşitli güvenlik ürünlerinden ve sensörlerden telemetri verilerini toplar ve analiz eder.
    - **Katmanlar Arası Tespit:** Bu farklı güvenlik katmanları arasındaki verileri ilişkilendirir ve analiz eder, tehditler ve saldırılar hakkında daha kapsamlı bir görünüm sağlar.
- **Yetenekler:**
    - **Birleşik Görünürlük:** Farklı ortamlar ve güvenlik ürünleri arasındaki güvenlik olayları ve olaylarına birleşik bir görünüm sunar.
    - **Otomatik Yanıt:** Olaylara otomasyon ve orkestrasyon kullanarak yanıt verir, yalnızca uç noktalarla sınırlı değildir.
    - **Gelişmiş Analitik:** Gelişmiş analitik, tehdit istihbaratı ve makine öğrenimi kullanarak, çeşitli saldırı vektörleri arasında yayılan karmaşık ve çok aşamalı saldırıları tespit eder.
- **Faydalar:**
    - Çeşitli güvenlik kaynaklarından gelen verileri entegre ederek ve ilişkilendirerek gelişmiş tehdit tespiti ve yanıt yetenekleri sağlar ve sofistike tehditlerin daha hızlı ve daha doğru bir şekilde tespit edilmesini sağlayarak genel güvenlik duruşunu geliştirir.
- **Özet:**
    - EDR, uç nokta seviyesinde tehdit tespiti ve yanıtına odaklanır, uç nokta düzeyinde derin görünürlük ve hızlı olay yanıtı yetenekleri sağlar.
    - XDR, uç noktaların ötesine geçerek, birden fazla güvenlik katmanından telemetri verilerini entegre eder ve ilişkilendirir, çeşitli saldırı vektörleri ve ortamlar boyunca tehditleri tespit ve yanıt verme konusunda birleşik bir yaklaşım sunar.

### Olay ve Akış Kavramları

- **Olay (Event):** Belirli bir zamanda gerçekleşen bir eylemin kaydıdır. Örneğin, bir kullanıcı giriş yaptıysa veya bir VPN bağlantısı kurulduysa, bu eylem o anda kaydedilir.
- **Akış (Flow):** Bir ağ aktivitesinin kaydını tutar ve bu aktivite birkaç saniye, dakika, saat veya gün sürebilir. Örneğin, bir web isteği birden fazla dosya (görsel, video vb.) indirebilir ve bu işlem 5-10 saniye sürebilir. Akış, iki ana bilgisayar arasındaki ağ aktivitesinin kaydını tutar.

### MITRE ATT&CK Çerçevesi

- **MITRE ATT&CK Framework:** Düşman taktikleri, teknikleri ve yaygın bilgi çerçevesidir. Gerçek dünyadan gözlemlenen düşman taktikleri ve tekniklerinin küresel olarak erişilebilir bir bilgi tabanıdır. ATT&CK, siber saldırılarda düşmanların kullandığı taktikleri ve teknikleri anlamalarına yardımcı olarak daha iyi tehdit tespiti, önleme ve yanıt sağlar.

### IDS Nedir?

- **Intrusion Detection System (IDS):** Bir ağ veya ana bilgisayarı izleyerek güvenlik ihlallerini ve saldırıları tespit etmek için kullanılan donanım veya yazılımdır.

### IPS Nedir?

- **Intrusion Prevention System (IPS):** Bir ağ veya ana bilgisayarı izleyerek güvenlik ihlallerini tespit eden ve gerekli önlemleri alarak bu ihlalleri engelleyen donanım veya yazılımdır.

### Güvenlik Duvarı (Firewall) Nedir?

- **Güvenlik Duvarı (Firewall):** Ağ trafiğini belirli kurallar çerçevesinde izleyen ve yönlendiren güvenlik yazılımı veya donanımıdır. Gelen ve giden ağ paketlerinin kurallara göre geçişine izin verir veya engeller.

### Güvenlik Duvarı Türleri

1. **Paket Filtreleme Güvenlik Duvarları**
    - **Fonksiyon:** Ağa geçen her paketi inceler ve kullanıcı tarafından tanımlanan kurallara göre kabul eder veya reddeder.
    - **Artıları:** Basit ve temel filtreleme için etkili.
    - **Eksileri:** Karmaşık saldırıları tespit etme kapasitesi sınırlıdır ve atlatılabilir.
2. **Durum Denetimi Güvenlik Duvarları**
    - **Fonksiyon:** Aktif bağlantıların durumunu izler ve trafiğin bağlamına göre karar verir (durum ve paket özellikleri).
    - **Artıları:** Paket filtrelemeden daha güvenlidir çünkü bağlantıların durumunu anlar.
    - **Eksileri:** Daha karmaşık ve kaynak tüketicidir.
3. **Vekil Güvenlik Duvarları (Uygulama Seviyesi Ağ Geçitleri)**
    - **Fonksiyon:** Son kullanıcılar ile erişim sağladıkları hizmetler arasında aracı olarak hareket eder, trafiği uygulama katmanında inceler.
    - **Artıları:** Trafiğin derinlemesine incelenmesini sağlar ve belirli içerikleri filtreleyebilir.
    - **Eksileri:** Gecikmeye neden olabilir ve kaynak tüketimi yüksektir.
4. **Yeni Nesil Güvenlik Duvarları (NGFW)**
    - **Fonksiyon:** Geleneksel güvenlik duvarı özelliklerini, saldırı önleme, derin paket inceleme ve uygulama farkındalığı gibi ek güvenlik işlevleriyle birleştirir.
    - **Artıları:** Geniş bir tehdit yelpazesine karşı kapsamlı koruma sunar.
    - **Eksileri:** Daha pahalıdır ve yapılandırılması ve bakımı daha karmaşıktır.
5. **Birleşik Tehdit Yönetimi (UTM) Güvenlik Duvarları**
    - **Fonksiyon:** Güvenlik duvarı, VPN, antivirüs, saldırı tespiti/önleme ve içerik filtreleme gibi birçok güvenlik özelliğini tek bir cihazda entegre eder.
    - **Artıları:** Yönetimi basitleştirir ve tek bir pakette kapsamlı güvenlik sağlar.
    - **Eksileri:** Tek bir arıza noktası olabilir ve her güvenlik işlevi için özel çözümler kadar etkili olmayabilir.
6. **Web Uygulama Güvenlik Duvarları (WAF)**
    - **Fonksiyon:** Web uygulamalarını HTTP/HTTPS trafiğini izleyerek ve filtreleyerek korumak için özel olarak tasarlanmıştır.
    - **Artıları:** SQL enjeksiyonu, XSS gibi web tabanlı saldırılara karşı etkilidir.
    - **Eksileri:** Yalnızca web uygulaması trafiği ile sınırlıdır ve diğer ağ trafiği türlerini korumak için uygun değildir.
7. **Yazılım Güvenlik Duvarları**
    - **Fonksiyon:** Bireysel bilgisayarlara veya sunuculara kurulur ve yetkisiz erişim ve tehditlerden korur.
    - **Artıları:** Esnek ve güncellenmesi kolaydır, bireysel cihaz koruması için uygundur.
    - **Eksileri:** Sistem kaynaklarını tüketebilir.

### Güvenlik Duvarlarının Kayıt Kaynakları

- Güvenlik duvarı ürünleri, ağ tabanlı filtreleme yaptığı için ağ akışı hakkında kayıtlar tutar. Örneğin:
    - Tarih/Saat bilgileri, Kaynak, Hedef IP Adresi, Kaynak ve Hedef Port, Eylem Bilgisi, Gönderilen ve Alınan Paket Sayısı.

### Web Uygulama Güvenlik Duvarı (WAF) Nedir?

- **Web Uygulama Güvenlik Duvarı (WAF):** Web uygulamalarına gelen ve giden paketleri izleyen, filtreleyen ve engelleyen güvenlik yazılımı veya donanımıdır.

### Web Uygulama Güvenlik Duvarı (WAF) Nasıl Çalışır?

- WAF, mevcut kurallara göre gelen uygulama trafiğini yönetir. Bu istekler, HTTP protokolüne ait olup kurallara göre ya kabul edilir ya da engellenir. Uygulama katmanı seviyesinde çalıştığı için web tabanlı saldırıları önleyebilir.

### Senaryolar ve Yanıtlar

1. **Ransomware Saldırısı:**
    - **Tespit:**
        1. Erken Belirtiler:
            - Ekranda bir fidye mesajı görünmesi.
            - Dosyaların erişilemez hale gelmesi ve alışılmadık uzantılar alması.
            - Cihazın performansının belirgin şekilde yavaşlaması.
        2. Cihazı İzole Etme:
            - Enfekte cihazı yerel ağdan ve internetten hemen ayırarak ransomware'in diğer cihazlara yayılmasını önleyin.
        3. Güvenlik Yazılımını Kullanma:
            - Cihazın tamamını taramak için antivirüs veya anti-malware programı çalıştırın. Bazı antivirüs programları belirli ransomware türlerini tespit edip kaldırabilir.
        4. Kayıtları ve Şüpheli Etkinlikleri Kontrol Etme:
            - Sistem kayıtlarını ve son aktiviteleri gözden geçirerek herhangi bir saldırı veya enfeksiyon belirtisi arayın.
    - **Önleme:**
        1. Şüpheli Dosyaları İzole Etme:
            - Enfekte veya şüpheli dosyaları izole ederek ransomware'in yayılmasını önleyin.
        2. Yedekten Geri Yükleme:
            - Enfeksiyondan önce alınmış yedeklerden dosyalarınızı geri yükleyin. Yedeklerin enfekte cihazla aynı ağda bulunmadığından emin olun.
        3. Cihazı Temizleme:
            - Ransomware kaldırma aracı veya antivirüs programı kullanarak cihazı ransomware'den temizleyin.
    - **Kayıt Kaynakları:**
        - Güvenlik Duvarı Kayıtları, Ağ Kayıtları ve Antivirüs/Anti-malware Kayıtları.
2. **Phishing Saldırısı:**
    - **Senaryo:**
        - Bir çalışan, güvenilir bir kaynaktan geldiği izlenimi veren bir aldatıcı e-posta alır ve bir bağlantıya tıklaması veya bir ek dosya indirmesi istenir.
    - **Yanıt:**
        1. Phishing E-postasını Tanıma:
            - Çalışanları phishing e-postalarını tanıma konusunda eğitin; şüpheli gönderen adresleri, genel selamlaşmaları ve acil dil kullanımını kontrol edin.
        2. İçeriği İzole Etme ve Bildirme:
            - Phishing e-postasını IT departmanına bildirin ve silin.
            - Gönderenin e-posta adresini ve domainini engelleyin.
        3. Kötü Amaçlı Yazılımı Tarama:
            - Bir ek dosya indirildiyse, cihazda hemen bir kötü amaçlı yazılım taraması yapın.
        4. Eğitim:
            - Phishing saldırı

larını tanıma ve ele alma konusunda düzenli eğitimler yapın.

- **Kayıtları Kontrol Etme:**
    - E-posta Sunucu Kayıtları: Olağandışı e-posta trafiğini veya yetkisiz erişim girişimlerini arayın.
    - Güvenlik Duvarı Kayıtları: Şüpheli dışa yönelik trafiği veya bilinen kötü niyetli IP adreslerine yapılan bağlantıları kontrol edin.
    - Uç Nokta Güvenliği Kayıtları: Antivirüs/anti-malware kayıtlarını tespit edilen tehditler için gözden geçirin.

### Veri İhlali (Data Breach)

- **Senaryo:** Hassas bilgilere yetkisiz bir taraf tarafından erişim sağlanır veya bu bilgiler çalınır.
- **Yanıt:**
    1. **İhlali Sınırlama:**
        - Etkilenen sistemleri ağdan ayırarak daha fazla veri kaybını önleyin.
    2. **Zafiyetleri Tanımlama ve Kapatma:**
        - İhlalin nasıl gerçekleştiğini belirlemek için kapsamlı bir araştırma yapın.
        - Herhangi bir zafiyeti kapatın ve ek güvenlik önlemleri uygulayın.
    3. **Etkilenen Tarafları Bilgilendirme:**
        - İhlalden etkilenen bireyler veya kuruluşlarla iletişime geçin.
    4. **Güvenliği Artırma:**
        - Kapsamlı bir güvenlik incelemesi yapın ve gelecekteki ihlalleri önlemek için önlemleri güçlendirin.
- **Kontrol Edilecek Kayıtlar:**
    - **Erişim Kayıtları:** Sunucular, veritabanları ve uygulamalardan yetkisiz erişim girişimlerini gözden geçirin.
    - **Sistem Olay Kayıtları:** Başarısız giriş girişimleri veya kullanıcı izinlerindeki değişiklikler gibi olağandışı aktiviteleri kontrol edin.
    - **Ağ Kayıtları:** Güvenlik duvarları ve saldırı tespit/önleme sistemlerinden gelen kayıtları şüpheli trafik desenleri için analiz edin.

### Sonuç ve Genel Tavsiyeler

- **Senaryoların Çeşitliliği:** Senaryolar çok sayıda olabilir ve bitmeyebilir, ancak yöntemler genellikle aynıdır:
    1. **Nasıl Tespit Edilir?**
    2. **Yanıt Ne Olacak?**
    3. **Mitigasyon (Önleme) Ne Olacak?**
- **Önemli Not:** Umarım her şeyi açıklığa kavuşturabilmişimdir. Kardeşiniz Ahmed Suleyman'ı ve Filistin'deki kardeşlerimizi dualarınızda unutmayın. Herhangi bir ihtiyaç durumunda LinkedIn veya WhatsApp üzerinden iletişime geçebilirsiniz.
