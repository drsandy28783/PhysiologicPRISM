# Use official Python image
FROM python:3.11-slim

# Install wkhtmltopdf dependencies
RUN apt-get update && apt-get install -y \
    wkhtmltopdf \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxrender1 \
    libxext6 \
    libx11-6 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy everything
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port (if not set by Render automatically)
EXPOSE 5000

# Start Flask app using Gunicorn
CMD ["gunicorn", "app:app"]
