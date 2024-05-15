#!/bin/bash
# Start FastAPI
uvicorn fastapi_app:app --host 0.0.0.0 --port 8000 &
# Start Streamlit
streamlit run streamlit_app.py --server.port 8501 &
wait