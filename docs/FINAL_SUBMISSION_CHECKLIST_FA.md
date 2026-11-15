# چک‌لیست تحویل نهایی پروژه PatchGuard — گروه ۱۱

## وضعیت اثبات‌شده تا ۱۵ نوامبر ۲۰۲۶

طبق خروجی واقعی اعلام‌شده از اجرای GitHub Actions در شاخه `main`، هر دو اجرای زیر موفق بوده‌اند:

- PatchGuard CI — Run `43748682438`: `success`.
- PatchGuard Full Quality Gate — Run `43748682537`: `success`.

این شماره اجراها مربوط به **کامیت همان زمان** هستند. بعد از هر Push جدید، اجرای GitHub Actions تازه باید دوباره بررسی شود.

## کنترل نهایی مخزن

- [ ] یک Clone تازه از شاخه `main` در محیط تمیز انجام شود.
- [ ] دستور `bash tools/docker_run.sh` خروجی `Scenario matrix PASS` بدهد.
- [ ] دستور `python3 -m unittest discover -s tests -v` تمام آزمون‌ها را موفق ثبت کند.
- [ ] دستور `python3 tools/blind_patch_test.py` نتیجه `9/9 passed` بدهد.
- [ ] دستور `python3 tools/quality_gate.py --strict` نتیجه `PASS` و صفر خطا/هشدار داشته باشد.
- [ ] دو Workflow مربوط به **آخرین کامیت** در GitHub Actions سبز باشند.
- [ ] فایل‌های `targets/frame/{base,correct,incomplete,regression}.c` موجود باشند.
- [ ] فایل‌های `targets/cjsonreal/{base,correct,incomplete,regression}.c`، سورس upstream، `LICENSE` و `source_manifest.json` موجود باشند.
- [ ] فایل‌های اوراکل مستقل `docs/oracle-frame.md` و `docs/oracle-cjsonreal.md` مرور شوند.
- [ ] یک نمونه گزارش JSON، گزارش Markdown و بستهٔ Reproducer/Minimization قابل‌بازتولید ارائه شود.
- [ ] پوشه‌های `artifacts/` از نظر خروجی‌های قدیمی و گزارش‌های تکراری بررسی شوند؛ گزارش کهنه به عنوان نتیجهٔ آخرین کامیت معرفی نشود.
- [ ] هیچ رمز، توکن، کلید خصوصی یا فایل محلی حساس در مخزن منتشر نشده باشد.
- [ ] منشأ کد و مجوز MIT مربوط به cJSON نگهداری شده باشد.
- [ ] README به‌اشتباه `jsonc` قدیمی را هدف اصلی معرفی نکند.
- [ ] تأیید مدرس/TA دربارهٔ هدف‌ها و اوراکل‌ها واقعاً دریافت و ثبت شود. **موفقیت CI جایگزین تأیید نیست.**
- [ ] مشارکت واقعی چهار نفر با شواهد قابل استناد ثبت شود؛ برای فردی کار انجام‌نشده نوشته نشود.
- [ ] هر عضو بتواند معماری، کد بخش مرتبط، یافته‌های امنیتی، خروجی‌ها و یک تغییر کوچک زنده را مستقل توضیح دهد.

## آزمایش مستقل، بدون دست‌کاری پوشهٔ اصلی

از ترمینال WSL، با Docker Desktop روشن:

```bash
cd /tmp
git clone https://github.com/pooryaamirniya/DNS_Project_G11.git patchguard-clean-check
cd patchguard-clean-check
bash tools/docker_run.sh
python3 -m unittest discover -s tests -v
python3 tools/blind_patch_test.py
python3 tools/quality_gate.py --strict
```

اگر `/tmp/patchguard-clean-check` از قبل موجود است، نام مقصد جدیدی انتخاب کنید؛ آن پوشه را بدون بررسی حذف نکنید.

## بررسی Workflowهای آخرین کامیت

```bash
gh run list -R pooryaamirniya/DNS_Project_G11 --limit 6
```

برای بررسی لاگ اجرای ناموفق:

```bash
gh run view RUN_ID -R pooryaamirniya/DNS_Project_G11 --log-failed
```

## دفاع فردی

طبق صورت پروژه، دفاع هر نفر جداگانه سنجیده می‌شود: ۳ امتیاز معماری و کد، ۳ امتیاز تحلیل شواهد و ۴ امتیاز تغییر محدود زنده. **سهم واقعی هر نفر باید ثبت و قابل دفاع باشد.** جدول مشارکت در `docs/TEAM_CONTRIBUTIONS_TEMPLATE_FA.md` موجود است.

## هشدارهای مهم

- «Pass» فقط در محدودهٔ ورودی‌ها و پیکربندی تست معنا دارد؛ اثبات رفع همهٔ آسیب‌پذیری‌های ممکن نیست.
- ابزار برای نسخه‌های ناقص و رگرسیونی باید عمداً نتیجهٔ غیرصفر بدهد؛ این به معنای شکست مجموعهٔ تستِ مورد انتظار نیست.
- اجرای باینری آسیب‌پذیر باید در کانتینر محدود یا ماشین مجازی آزمایشی انجام شود.
