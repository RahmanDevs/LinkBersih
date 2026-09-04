from django.shortcuts import render
from apps.core.services import PhishingDetectorService

def home_view(request):
    scan_result = None
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            scan_result = PhishingDetectorService.scan_and_save(url)
            
    # Pastikan request dilewatkan ke render()
    return render(request, 'index.html', {'scan_result': scan_result})