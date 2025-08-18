## قائمة المهام لمشروع O-Hunter

### المرحلة 1: استخراج وتحليل المشروع الحالي
- [x] استخراج ملف المشروع المضغوط.
- [x] مراجعة ملف README.md لفهم بنية المشروع وميزاته الحالية.
- [x] فحص المكونات الأساسية (CLI, Flask backend, React GUI).
- [x] تحديد نقاط التكامل لإضافة الميزات الجديدة.

### المرحلة 2: إضافة فحوصات جديدة (Core Enhancements)
- [x] دعم ثغرات متقدمة: SSRF, RCE, XXE, Open Redirect, HTTP Request Smuggling, Insecure Deserialization.
- [x] إضافة Directory Enumeration module (باستخدام dirsearch).
- [x] إضافة Weak Credentials checker (مع قائمة بسيطة).
- [x] دمج Masscan لعمل port scanning.
- [x] دمج Nmap + NSE scripts للكشف عن الخدمات والثغرات.
- [x] دمج Webanalyze (بديل مجاني لـ Wappalyzer) لتحديد الـ CMS والـ frameworks والتكنولوجيات.

### المرحلة 3: تحسين GUI (React Dashboard)
- [x] إضافة Dark mode.
- [x] تصميم Dashboard فيها Charts (باستخدام Recharts أو Chart.js) تعرض:
  - [x] عدد الثغرات حسب النوع.
  - [x] Severity levels (Critical, High, Medium, Low).
- [x] خيارات تشغيل سريعة (Quick Scan / Full Scan / Custom Scan).
- [x] دعم تحميل التقارير بصيغة PDF و HTML.

### المرحلة 4: تكامل مع APIs مجانية
- [x] دمج OWASP ZAP API في background لتوليد تقارير XSS/SQLi.
- [x] دمج HaveIBeenPwned Password API (الجزء المجاني) لتشييك الباسوردات الضعيفة.
- [x] دعم Censys Free API (250 query شهريًا) كاختياري في recon.

### المرحلة 5: تحسين الأداء
- [x] استخدام async/multithreading عشان السرعة في الفحص.
- [x] تصميم Plugin System بحيث أي حد يقدر يضيف module جديد بسهولة (Python plugins).

### المرحلة 6: SEO Optimization
- [x] إضافة meta tags لكل صفحة (title, description, keywords).
- [x] إضافة structured data (JSON-LD) خاصة بالـ Vulnerabilities.
- [x] Keywords تشمل أسماء الثغرات: XSS, SQLi, SSRF, RCE, CSRF, HTTP Smuggling, Directory Traversal, XXE, Open Redirect, Cloud misconfigurations, وغيرها.
- [x] Sitemap.xml و robots.txt متكاملين.
- [x] تحسين سرعة التحميل (minify CSS/JS, lazy load).
- [x] إضافة صفحات Landing لكل ثغرة (مثلاً: /xss, /sql-injection, /ssrf, إلخ) بشرح مختصر عن الثغرة، بحيث أي بحث عليها يجيب الموقع.
- [x] عمل Internal linking بين الصفحات.
- [x] إضافة OG tags + Twitter cards عشان تظهر كويس في السوشيال ميديا.

### المرحلة 7: اختبار وتوثيق التحسينات
- [x] إجراء اختبارات شاملة لجميع الميزات الجديدة.
- [x] تحديث الوثائق الفنية للمشروع.

### المرحلة 8: تسليم المشروع المحدث للمستخدم
- [ ] تجميع المشروع النهائي.
- [ ] تقديم تقرير بالتحسينات المنجزة.