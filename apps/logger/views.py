from django.core.paginator import Paginator
from django.shortcuts import render
from .models import ScanLog

def logger_view(request):
    """
    View untuk menampilkan halaman Log Monitor
    """
    search_query = request.GET.get("q", "")
    status_filter = request.GET.get("status", "all")
    page_number = request.GET.get("page", 1)

    logs = ScanLog.objects.all().order_by('-date_scanned')
    
    if search_query:
        logs = logs.filter(url__icontains=search_query)
    
    if status_filter != "all":
        logs = logs.filter(classification=status_filter)
    
    paginator = Paginator(logs, 20)
    page_obj = paginator.get_page(page_number)
    
    context = {
        "search_query": search_query,
        "status_filter": status_filter,
        "logs": page_obj,
    }
    return render(request, "logger/logger.html", context)