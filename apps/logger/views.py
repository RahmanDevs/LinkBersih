from django.shortcuts import render

def logger_view(request):
    """
    View untuk menampilkan halaman Log Monitor
    """
    search_query = request.GET.get("q", "")
    status_filter = request.GET.get("status", "all")

    # TODO: Ambil data riwayat log dari Database (Models) berdasarkan filter
    
    context = {
        "search_query": search_query,
        "status_filter": status_filter,
    }
    return render(request, "logger/logger.html", context)