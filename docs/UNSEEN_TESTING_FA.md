# مرحله سوم: آزمایش وصله‌های دیده‌نشده (Unseen Patches)

## هدف

ماتریس اصلی ۶ سناریویی بعد از واردکردن cJSON موفق بوده است. این فایل آزمایش اضافه‌ای است که قبل از جلسه دفاع اجرا می‌شود و نشان می‌دهد موتور طبقه‌بندی PatchGuard به **اسم فایل یا نام سناریو** وابسته نیست. **این آزمایش به‌تنهایی جایگزین وصله‌های واقعی ارائه‌شده توسط استاد یا تأیید مدرس نیست.**

## راه‌اندازی و اجرا

از ریشه پروژه `PatchGuard_Project1`:

```bash
python3 tools/blind_patch_test.py
```

این ابزار بدون دست‌کاری فایل‌های `runner.py`، `cli.py`، `Dockerfile`، `configs/*.json` یا سورس‌های اصلی:

- چند سورس C با نام‌های تصادفی بر اساس سورس صحیح موجود در `targets/frame/correct.c` و `targets/cjsonreal/correct.c` تولید می‌کند.
- برای هر سورس، پیکربندی مستقلی بر اساس آزمون‌ها و oracle قبلی ایجاد می‌کند؛ کد ارزیاب تنها source path متفاوت را می‌بیند.
- از Docker با network=none، read-only rootfs، حذف capabilityها و محدودیت منابع برای اجرای باینری استفاده می‌کند.
- نتیجه runtime را با انتظار آزمایش کنترل می‌کند، بدون واردکردن انتظار آزمایش به فایل config.
- جواب‌ها را در `artifacts/blind-patches/summary.json` می‌نویسد.

**خروجی هدف:** `Blind patch matrix: 9/9 passed` (هدف برای اجراست، نه نتیجه‌ای که قبلاً روی WSL شما تأیید شده باشد).

حالات شامل ۳ وصله صحیح/ناقص/رگرسیون برای هر برنامه، یک خطای امنیتی جدید برای frame، یک وضعیت inconclusive، و یک build error است. ورودی‌های حمله و oracle هر دو هدف از پیکربندی‌های قبلی استخراج می‌شوند. برای سناریوی عمداً بدون بازتولید، ورودی امنیتی معتبر به‌جای ورودی خطاساز داده می‌شود تا کد ۴۰ بررسی شود.

**نکته علمی:** سناریوها از نسخه‌های واقعی و وصله موجود مشتق می‌شوند، بنابراین آزمون *تعمیم نسبی با ورودی ناشناخته برای موتور* است، نه یک مطالعه مستقل روی یک CVE جدید.

## ارزیابی وصله جدید مدرس

فایل سورس جدید را در پوشه‌ای از پروژه (مثل `candidate_sources/changed.c`) بگذارید. فایل باید با آرایش سورس و adapter هدف مربوطه سازگار باشد، نه صرفاً یک diff متنی.

```bash
python3 tools/evaluate_candidate.py --target cjsonreal --source candidate_sources/changed.c
```

برای frame:

```bash
python3 tools/evaluate_candidate.py --target frame --source candidate_sources/changed.c
```

خروجی مستقیم برنامه می‌تواند 0، 10، 20، 30 یا 40 باشد و الزاماً 0 نیست. گزارش مستقل در `artifacts/candidate-evaluations/<hash>/run/report.json` قرار می‌گیرد. برای build mismatch یا استفاده از کامپایل چندفایلی باید adapter ساخت در پیکربندی اصلاح شود، نه اینکه بر اساس نام فایل تصمیم بگیریم.

## اشکالاتی که در صورت FAIL باید پیگیری شوند

- `frame` 40 با ASan `DEADLYSIGNAL`: بررسی پایداری ASan و گزینه `_FORTIFY_SOURCE` در باینری Sanitized.
- `cjsonreal` 40: بررسی `cJSON_SetValuestring`, گارد NULL، نسخه release واقعی و stack frameهای ASan.
- timeout یا Docker failure: وضعیت Docker Desktop، اتصال WSL2، حافظه و منابع Docker.
- خطای permission روی `/mnt/c`: پروژه را در فایل‌سیستم Linux مثل `~/PatchGuard_Project1` کپی کرده و آنجا اجرا کنید.
- `new_issue` با classification غیرمنتظره: گزارش واقعی stderr و signature را بخوانید؛ حدس نزنید.

## حفاظت از فایل‌های فعلی

تنها در `artifacts/blind-patches/` و `artifacts/candidate-evaluations/` فایل جدید می‌نویسد. هیچ یک از شش config اصلی، targets رسمی یا اسکریپت قبلی بازنویسی نمی‌شود. تغییرات ایجادشده برای `--minimize` ممکن است به‌صورت آزمایش‌های یادگرفته‌شده در `regressions/` اضافه شوند؛ بدون این گزینه minimization خاموش است.
