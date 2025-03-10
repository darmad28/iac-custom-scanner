# Usamos una imagen base de Python
FROM python:3.11-slim

# Configuración del directorio de trabajo
WORKDIR /app

# Copiar los archivos de la aplicación
COPY . /app/

# Instalar las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto en el que la app escuchará
EXPOSE 8080

# Comando para iniciar la aplicación
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
