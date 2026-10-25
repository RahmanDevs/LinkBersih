from django.core.cache import cache
from django.shortcuts import render
from apps.core.services import PhishingDetectorService


def get_client_ip(request):
    """Retrieve client IP address considering proxy headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def home_view(request):
    scan_result = None
    error_message = None

    if request.method == 'POST':
        # Rate Limiting: 20 scans per minute per client IP
        client_ip = get_client_ip(request)
        rate_key = f"ratelimit_scan_{client_ip}"
        request_count = cache.get(rate_key, 0)

        if request_count >= 20:
            error_message = "Terlalu banyak permintaan pemindaian. Batas 20 pemindaian per menit tercapai. Silakan coba lagi nanti."
            return render(
                request,
                'index.html',
                {'scan_result': None, 'error_message': error_message},
            )

        cache.set(rate_key, request_count + 1, timeout=60)

        raw_url = request.POST.get('url', '').strip()
        if not raw_url:
            error_message = "URL tidak boleh kosong."
        elif len(raw_url) > 2000:
            error_message = "URL terlalu panjang. Maksimum 2000 karakter diperbolehkan."
        else:
            try:
                scan_result = PhishingDetectorService.scan_and_save(raw_url)
            except ValueError as val_err:
                error_message = f"Validasi URL Gagal: {str(val_err)}"
            except Exception as exc:
                error_message = f"Terjadi kesalahan saat memproses URL: {str(exc)}"

    return render(
        request,
        'index.html',
        {'scan_result': scan_result, 'error_message': error_message},
    )
