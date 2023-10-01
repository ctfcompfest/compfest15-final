from django.shortcuts import render, redirect
from django.http import FileResponse
from reportlab.platypus import SimpleDocTemplate, Paragraph
from io import BytesIO

def index(request):
    return render(request, 'index.html')

def convert(request):
    if request.method == 'POST':
        user_input = request.POST.get('user_input', '')
        try:
            buffer = BytesIO()
            docs = SimpleDocTemplate(buffer)
            docs.build([Paragraph(user_input)])

            buffer.seek(0)

            response = FileResponse(buffer, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename=converted.pdf'
            return response
        except:
            pass

    return redirect("/")
