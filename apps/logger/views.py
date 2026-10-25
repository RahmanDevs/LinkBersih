from django.core.paginator import Paginator
from django.shortcuts import render
from .models import ScanLog


def logger_view(request):
    """
    View untuk menampilkan halaman Log Monitor dengan sanitasi input filter
    dan paginasi aman.
    """
    search_query = request.GET.get("q", "").strip()[:100]
    raw_status = request.GET.get("status", "all").strip()
    status_upper = raw_status.upper()
    page_number = request.GET.get("page", 1)

    logs = ScanLog.objects.all().order_by('-date_scanned')

    if search_query:
        logs = logs.filter(url__icontains=search_query)

    if status_upper != "ALL" and status_upper in ScanLog.Classification.values:
        logs = logs.filter(classification=status_upper)

    paginator = Paginator(logs, 20)
    page_obj = paginator.get_page(page_number)

    context = {
        "search_query": search_query,
        "status_filter": raw_status.lower(),
        "logs": page_obj,
    }
    return render(request, "logger/logger.html", context)
