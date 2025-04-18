FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir paramiko google-generativeai PyYAML Flask Flask-CORS markupsafe

COPY router_log_analyzer.py .
COPY secrets.yaml .
COPY secret_gemini.yaml .
COPY ./templates ./templates  

# Expose the port the Flask app will run on (default: 5000)
EXPOSE 5000

# Set environment variables (optional, but recommended for API key)
# ENV GEMINI_API_KEY="YOUR_GEMINI_API_KEY"  #  <--  DO NOT HARDCODE!  Use docker run -e ...

# Command to run the Flask app
CMD ["python", "router_log_analyzer.py"]
