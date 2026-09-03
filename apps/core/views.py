from django.shortcuts import render

def home_view(request):
    """
    View untuk menampilkan halaman utama (Home / Check Link)
    """
    if request.method == "POST":
        url_input = request.POST.get("url")
        # TODO: Tambahkan logic deteksi URL / pemanggilan AI service di sini
        
    return render(request, "index.html")