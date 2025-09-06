#!/usr/bin/env python3
"""
Combined Streamlit App for Hyperpure Gmail to Drive and PDF to Sheet Workflows
Modified to save attachments in existing Gmail_Attachments/Hyperpure GRN/PDFs/ with message ID prefix
"""

import streamlit as st
import os
import json
import base64
import tempfile
import time
import logging
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from io import BytesIO

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload

# Add LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="Hyperpure Automation Workflows",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hardcoded configuration
CONFIG = {
    'gmail': {
        'sender': 'noreply@hyperpure.com',
        'search_term': 'Hyperpure GRN',
        'gdrive_folder_id': '1euqxO-meY4Ahszpdk3XbwlRwvkfSlY8k',
        'attachment_filter': 'attachment.pdf'
    },
    'pdf': {
        'llama_api_key': 'llx-VZtsmttXKvmRWfzk4po2FPSlGBflR7bNvJoEaZ3adzTpewq1',
        'llama_agent': 'Hyperpure Agent',
        'drive_folder_id': '1aUjRMqWjVDDAsQw0TugwgmwYjxP6W7DT',
        'spreadsheet_id': '1B1C2ILnIMXpEYbQzaSkhRzEP2gmgE2YLRNqoX98GwcU',
        'sheet_range': 'hyperpuregrn'
    }
}

class HyperpureAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
        # Initialize logs in session state if not exists
        if 'logs' not in st.session_state:
            st.session_state.logs = []
    
    def log(self, message: str, level: str = "INFO"):
        """Add log entry with timestamp to session state"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp, 
            "level": level.upper(), 
            "message": message
        }
        
        st.session_state.logs.append(log_entry)
        
        # Keep only last 100 logs
        if len(st.session_state.logs) > 100:
            st.session_state.logs = st.session_state.logs[-100:]
    
    def get_logs(self):
        """Get logs from session state"""
        return st.session_state.get('logs', [])
    
    def clear_logs(self):
        """Clear all logs"""
        st.session_state.logs = []
    
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            self.log("Starting authentication process...", "INFO")
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful using cached token!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                    elif creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful after token refresh!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                    else:
                        self.log("Cached token invalid or expired without refresh token", "WARNING")
                except Exception as e:
                    self.log(f"Cached token invalid: {str(e)}", "WARNING")
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("redirect_uri", "https://hyperpuregrn.streamlit.app/")
                )
                
                # Generate authorization URL
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                # Check for callback code
                query_params = st.query_params
                self.log(f"Raw query parameters: {dict(query_params)}", "DEBUG")
                if "code" in query_params:
                    try:
                        code = query_params["code"]
                        if isinstance(code, list):
                            code = code[0] if code else ""
                        if not code:
                            raise ValueError("Authorization code is empty or missing")
                        self.log(f"Received auth code: {code[:10]}...", "DEBUG")
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        # Save credentials in session state
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_bar.progress(100)
                        self.log("OAuth authentication successful!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        self.log(f"OAuth authentication failed: {str(e)}", "ERROR")
                        st.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    self.log("No authorization code in query parameters", "WARNING")
                    # Show authorization link
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Click here to authorize with Google]({auth_url})")
                    self.log("Waiting for user to authorize application", "INFO")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                self.log("Google credentials missing in Streamlit secrets", "ERROR")
                st.error("Google credentials missing in Streamlit secrets")
                return False
                
        except Exception as e:
            self.log(f"Authentication failed: {str(e)}", "ERROR")
            st.error(f"Authentication failed: {str(e)}")
            return False
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                      days_back: int = 7, max_results: int = 50) -> List[Dict]:
        try:
            query_parts = ["has:attachment"]
            if sender:
                query_parts.append(f'from:"{sender}"')
            if search_term:
                query_parts.append(f'"{search_term}"')
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            query = " ".join(query_parts)
            self.log(f"Gmail search query: {query}", "INFO")
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            messages = result.get('messages', [])
            self.log(f"Found {len(messages)} emails matching criteria", "SUCCESS")
            return messages
        except Exception as e:
            self.log(f"Gmail search failed: {str(e)}", "ERROR")
            return []
    
    def get_email_details(self, message_id: str) -> Dict:
        try:
            message = self.gmail_service.users().messages().get(
                userId='me', id=message_id, format='metadata'
            ).execute()
            headers = message['payload'].get('headers', [])
            details = {
                'id': message_id,
                'sender': next((h['value'] for h in headers if h['name'] == "From"), "Unknown"),
                'subject': next((h['value'] for h in headers if h['name'] == "Subject"), "(No Subject)"),
                'date': next((h['value'] for h in headers if h['name'] == "Date"), "")
            }
            return details
        except Exception as e:
            self.log(f"Failed to get email details for {message_id}: {str(e)}", "ERROR")
            return {}
    
    def find_target_folder(self, parent_folder_id: str) -> Optional[str]:
        """Find the PDFs folder in Gmail_Attachments/Hyperpure GRN/PDFs/"""
        try:
            # Find Gmail_Attachments folder
            query = f"name='Gmail_Attachments' and mimeType='application/vnd.google-apps.folder' and '{parent_folder_id}' in parents and trashed=false"
            result = self.drive_service.files().list(q=query, fields='files(id)').execute()
            files = result.get('files', [])
            if not files:
                self.log("Gmail_Attachments folder not found", "ERROR")
                return None
            gmail_folder_id = files[0]['id']
            
            # Find Hyperpure GRN folder
            query = f"name='Hyperpure GRN' and mimeType='application/vnd.google-apps.folder' and '{gmail_folder_id}' in parents and trashed=false"
            result = self.drive_service.files().list(q=query, fields='files(id)').execute()
            files = result.get('files', [])
            if not files:
                self.log("Hyperpure GRN folder not found", "ERROR")
                return None
            hyperpure_folder_id = files[0]['id']
            
            # Find PDFs folder
            query = f"name='PDFs' and mimeType='application/vnd.google-apps.folder' and '{hyperpure_folder_id}' in parents and trashed=false"
            result = self.drive_service.files().list(q=query, fields='files(id)').execute()
            files = result.get('files', [])
            if not files:
                self.log("PDFs folder not found", "ERROR")
                return None
            return files[0]['id']
        except Exception as e:
            self.log(f"Failed to find target folder: {str(e)}", "ERROR")
            return None
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str, message_id: str) -> bool:
        """Upload file to Google Drive with message ID prefix"""
        try:
            prefixed_filename = f"{message_id}_{filename}"
            query = f"name='{prefixed_filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            if existing.get('files', []):
                self.log(f"File already exists, skipping: {prefixed_filename}", "INFO")
                return True
            file_metadata = {
                'name': prefixed_filename,
                'parents': [folder_id]
            }
            media = MediaIoBaseUpload(
                BytesIO(file_data),
                mimetype='application/pdf',
                resumable=True
            )
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            self.log(f"Uploaded to Drive: {prefixed_filename}", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Failed to upload {prefixed_filename}: {str(e)}", "ERROR")
            return False
    
    def process_attachment(self, message_id: str, part: Dict, folder_id: str) -> bool:
        try:
            filename = part.get("filename", "").lower()
            if filename != CONFIG['gmail']['attachment_filter'].lower():
                return False
            att_id = part["body"].get("attachmentId")
            if not att_id:
                return False
            att = self.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=att_id
            ).execute()
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            return self.upload_to_drive(file_data, filename, folder_id, message_id)
        except Exception as e:
            self.log(f"Failed to process attachment for message {message_id}: {str(e)}", "ERROR")
            return False
    
    def extract_attachments_from_email(self, message_id: str, payload: Dict, folder_id: str) -> int:
        count = 0
        if "parts" in payload:
            for part in payload["parts"]:
                count += self.extract_attachments_from_email(message_id, part, folder_id)
        if "filename" in payload and "attachmentId" in payload.get("body", {}):
            if self.process_attachment(message_id, payload, folder_id):
                count += 1
        return count
    
    def process_gmail_workflow(self, config: dict, progress_callback=None, status_callback=None):
        try:
            if status_callback:
                status_callback("Starting Gmail workflow...")
            self.log("Starting Gmail to Drive workflow", "INFO")
            
            # Find the target PDFs folder
            target_folder_id = self.find_target_folder(config['gdrive_folder_id'])
            if not target_folder_id:
                self.log("Target folder structure not found", "ERROR")
                return {'success': False, 'processed': 0}
            
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results']
            )
            if progress_callback:
                progress_callback(25)
            if not emails:
                self.log("No emails found matching criteria", "WARNING")
                return {'success': True, 'processed': 0}
            if status_callback:
                status_callback(f"Found {len(emails)} emails. Processing attachments...")
            
            processed_count = 0
            for i, email in enumerate(emails):
                if status_callback:
                    status_callback(f"Processing email {i+1}/{len(emails)}")
                message = self.gmail_service.users().messages().get(
                    userId='me', id=email['id']
                ).execute()
                att_count = self.extract_attachments_from_email(email['id'], message['payload'], target_folder_id)
                if att_count > 0:
                    processed_count += att_count
                if progress_callback:
                    progress = 50 + (i + 1) / len(emails) * 45
                    progress_callback(int(progress))
            if progress_callback:
                progress_callback(100)
            if status_callback:
                status_callback(f"Gmail workflow completed! Processed {processed_count} attachments")
            self.log(f"Gmail workflow completed. Processed {processed_count} attachments", "SUCCESS")
            return {'success': True, 'processed': processed_count}
        except Exception as e:
            self.log(f"Gmail workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'processed': 0}
    
    def list_drive_pdfs(self, folder_id: str, days_back: int = 1) -> List[Dict]:
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back - 1)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime >= '{start_str}'"
            files = []
            page_token = None
            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, createdTime)",
                    orderBy="createdTime desc",
                    pageToken=page_token,
                    pageSize=100
                ).execute()
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            self.log(f"Found {len(files)} PDF files in folder (last {days_back} days)", "INFO")
            return files
        except Exception as e:
            self.log(f"Failed to list PDFs: {str(e)}", "ERROR")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        try:
            self.log(f"Downloading: {file_name}", "INFO")
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            self.log(f"Downloaded: {file_name}", "SUCCESS")
            return file_data
        except Exception as e:
            self.log(f"Failed to download {file_name}: {str(e)}", "ERROR")
            return b""
    
    def get_sheet_data(self, spreadsheet_id: str, sheet_name: str) -> List[List[str]]:
        """Get all data from the sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_name,
                majorDimension="ROWS"
            ).execute()
            return result.get('values', [])
        except Exception as e:
            self.log(f"Failed to get sheet data: {str(e)}", "ERROR")
            return []
    
    def get_sheet_id(self, spreadsheet_id: str, sheet_name: str) -> int:
        """Get the numeric sheet ID for the given sheet name"""
        try:
            metadata = self.sheets_service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
            for sheet in metadata.get('sheets', []):
                if sheet['properties']['title'] == sheet_name:
                    return sheet['properties']['sheetId']
            self.log(f"Sheet '{sheet_name}' not found", "ERROR")
            return 0
        except Exception as e:
            self.log(f"Failed to get sheet metadata: {str(e)}", "ERROR")
            return 0
    
    def get_existing_drive_ids(self, spreadsheet_id: str, sheet_range: str) -> set:
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range,
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            if not values:
                return set()
            headers = values[0]
            if "drive_file_id" not in headers:
                self.log("No 'drive_file_id' column found in sheet", "WARNING")
                return set()
            id_index = headers.index("drive_file_id")
            existing_ids = {row[id_index] for row in values[1:] if len(row) > id_index and row[id_index]}
            self.log(f"Found {len(existing_ids)} existing file IDs in sheet", "INFO")
            return existing_ids
        except Exception as e:
            self.log(f"Failed to get existing file IDs: {str(e)}", "ERROR")
            return set()
    
    def _get_sheet_headers(self, spreadsheet_id: str, sheet_range: str) -> List[str]:
        try:
            sheet_name = sheet_range.split('!')[0]
            header_range = f"{sheet_name}!A1:AAA1"
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=header_range,
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            headers = values[0] if values else []
            self.log(f"Fetched {len(headers)} existing headers from sheet", "INFO")
            return headers
        except Exception as e:
            self.log(f"Failed to get sheet headers: {str(e)}", "ERROR")
            return []
    
    def _update_sheet_headers(self, spreadsheet_id: str, sheet_range: str, new_headers: List[str]):
        try:
            sheet_name = sheet_range.split('!')[0]
            end_col = chr(64 + len(new_headers))
            header_range = f"{sheet_name}!A1:{end_col}1"
            body = {'values': [new_headers]}
            self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=header_range,
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            self.log(f"Updated sheet headers to {len(new_headers)} columns", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Failed to update sheet headers: {str(e)}", "ERROR")
            return False
    
    def _append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]], max_retries: int = 3):
        """Append data to Google Sheet with retry mechanism"""
        for attempt in range(1, max_retries + 1):
            try:
                body = {'values': values}
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=spreadsheet_id, 
                    range=range_name,
                    valueInputOption='USER_ENTERED', 
                    body=body
                ).execute()
                updated_cells = result.get('updates', {}).get('updatedCells', 0)
                self.log(f"Appended {updated_cells} cells to Google Sheet", "SUCCESS")
                return True
            except Exception as e:
                if attempt < max_retries:
                    self.log(f"Append attempt {attempt} failed: {str(e)}", "WARNING")
                    time.sleep(2)
                else:
                    self.log(f"Failed to append to Google Sheet after {max_retries} attempts: {str(e)}", "ERROR")
                    return False
        return False
    
    def replace_rows_for_file(self, spreadsheet_id: str, sheet_name: str, file_id: str, 
                             headers: List[str], new_rows: List[List[Any]], sheet_id: int) -> bool:
        """Delete existing rows for the file if any, and append new rows"""
        try:
            values = self.get_sheet_data(spreadsheet_id, sheet_name)
            if not values:
                return self._append_to_google_sheet(spreadsheet_id, sheet_name, new_rows)
            
            current_headers = values[0]
            data_rows = values[1:]
            
            try:
                file_id_col = current_headers.index('drive_file_id')
            except ValueError:
                self.log("No 'drive_file_id' column found, appending new rows", "INFO")
                return self._append_to_google_sheet(spreadsheet_id, sheet_name, new_rows)
            
            rows_to_delete = []
            for idx, row in enumerate(data_rows, 2):
                if len(row) > file_id_col and row[file_id_col] == file_id:
                    rows_to_delete.append(idx)
            
            if rows_to_delete:
                rows_to_delete.sort(reverse=True)
                requests = []
                for row_idx in rows_to_delete:
                    requests.append({
                        'deleteDimension': {
                            'range': {
                                'sheetId': sheet_id,
                                'dimension': 'ROWS',
                                'startIndex': row_idx - 1,
                                'endIndex': row_idx
                            }
                        }
                    })
                body = {'requests': requests}
                self.sheets_service.spreadsheets().batchUpdate(
                    spreadsheetId=spreadsheet_id,
                    body=body
                ).execute()
                self.log(f"Deleted {len(rows_to_delete)} existing rows for file {file_id}", "INFO")
            
            return self._append_to_google_sheet(spreadsheet_id, sheet_name, new_rows)
        except Exception as e:
            self.log(f"Failed to replace rows: {str(e)}", "ERROR")
            return False
    
    def process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        rows = []
        items = []
        if "items" in extracted_data:
            items = extracted_data["items"]
        elif "product_items" in extracted_data:
            items = extracted_data["product_items"]
        else:
            self.log(f"No recognizable items key in {file_info['name']}", "WARNING")
            return rows
        for item in items:
            item["po_number"] = extracted_data.get("po_number") or extracted_data.get("purchase_order_number") or ""
            item["vendor_invoice_number"] = extracted_data.get("vendor_invoice_number") or extracted_data.get("invoice_number") or extracted_data.get("supplier_bill_number") or ""
            item["supplier"] = extracted_data.get("supplier") or extracted_data.get("vendor") or ""
            item["shipping_address"] = extracted_data.get("shipping_address") or extracted_data.get("receiver_address") or extracted_data.get("Shipping Address") or ""
            item["grn_date"] = extracted_data.get("grn_date") or extracted_data.get("delivered_on") or ""
            item["source_file"] = file_info['name']
            item["processed_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            item["drive_file_id"] = file_info['id']
            cleaned_item = {k: v for k, v in item.items() if v not in ["", None]}
            rows.append(cleaned_item)
        return rows
    
    def safe_extract(self, agent, file_path: str, retries: int = 3):
        for attempt in range(1, retries + 1):
            try:
                self.log(f"Extracting data (attempt {attempt}/{retries})...", "INFO")
                result = agent.extract(file_path)
                self.log("Extraction successful", "SUCCESS")
                return result
            except Exception as e:
                self.log(f"Extraction attempt {attempt} failed: {str(e)}", "WARNING")
                time.sleep(2)
        self.log(f"Extraction failed after {retries} attempts", "ERROR")
        return None
    
    def process_pdf_workflow(self, config: dict, progress_callback=None, status_callback=None, skip_existing: bool = False):
        if not LLAMA_AVAILABLE:
            self.log("LlamaParse not available", "ERROR")
            return {'success': False, 'processed': 0, 'rows_added': 0, 'failed': 0}
        try:
            if status_callback:
                status_callback("Starting PDF to Sheet workflow...")
            self.log("Starting PDF to Sheet workflow", "INFO")
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            if agent is None:
                self.log(f"Could not find agent '{config['llama_agent']}'", "ERROR")
                return {'success': False, 'processed': 0, 'rows_added': 0, 'failed': 0}
            self.log("LlamaParse agent found", "SUCCESS")
            sheet_name = config['sheet_range'].split('!')[0]
            sheet_id = self.get_sheet_id(config['spreadsheet_id'], sheet_name)
            existing_ids = set()
            if skip_existing:
                existing_ids = self.get_existing_drive_ids(config['spreadsheet_id'], config['sheet_range'])
            pdf_files = self.list_drive_pdfs(config['drive_folder_id'], config['days_back'])
            if skip_existing:
                pdf_files = [f for f in pdf_files if f['id'] not in existing_ids]
                self.log(f"After filtering, {len(pdf_files)} PDFs to process", "INFO")
            max_files = config.get('max_files', len(pdf_files))
            pdf_files = pdf_files[:max_files]
            if progress_callback:
                progress_callback(25)
            if not pdf_files:
                self.log("No PDF files found", "WARNING")
                if status_callback:
                    status_callback("No PDF files found in the specified folder")
                return {'success': True, 'processed': 0, 'rows_added': 0, 'failed': 0}
            if status_callback:
                status_callback(f"Found {len(pdf_files)} PDF files. Processing...")
            existing_headers = self._get_sheet_headers(config['spreadsheet_id'], config['sheet_range'])
            headers_set = not bool(existing_headers)
            processed_count = 0
            rows_added = 0
            failed_count = 0
            for i, file in enumerate(pdf_files):
                if status_callback:
                    status_callback(f"Processing PDF {i+1}/{len(pdf_files)}: {file['name']}")
                self.log(f"Processing PDF {i+1}/{len(pdf_files)}: {file['name']}", "INFO")
                pdf_data = self.download_from_drive(file['id'], file['name'])
                if not pdf_data:
                    failed_count += 1
                    continue
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
                    temp_file.write(pdf_data)
                    temp_path = temp_file.name
                result = self.safe_extract(agent, temp_path)
                os.unlink(temp_path)
                if not result:
                    failed_count += 1
                    continue
                extracted_data = result.data
                rows = self.process_extracted_data(extracted_data, file)
                if not rows:
                    self.log(f"No rows extracted from: {file['name']}", "WARNING")
                    failed_count += 1
                    continue
                processed_count += 1
                self.log(f"Successfully processed: {file['name']}", "SUCCESS")
                self.log(f"Extracted {len(rows)} rows from this PDF", "INFO")
                if not existing_headers and not headers_set:
                    all_keys = list(set().union(*(row.keys() for row in rows)))
                    existing_headers = all_keys
                    self._update_sheet_headers(config['spreadsheet_id'], config['sheet_range'], existing_headers)
                    headers_set = True
                all_keys = list(set().union(*(row.keys() for row in rows)))
                new_headers = list(set(existing_headers + all_keys))
                if len(new_headers) > len(existing_headers):
                    self._update_sheet_headers(config['spreadsheet_id'], config['sheet_range'], new_headers)
                    existing_headers = new_headers
                values = [[row.get(h, "") for h in existing_headers] for row in rows]
                success = self.replace_rows_for_file(
                    spreadsheet_id=config['spreadsheet_id'],
                    sheet_name=sheet_name,
                    file_id=file['id'],
                    headers=existing_headers,
                    new_rows=values,
                    sheet_id=sheet_id
                )
                if success:
                    rows_added += len(rows)
                    self.log(f"Successfully saved {len(rows)} rows for this PDF", "SUCCESS")
                else:
                    self.log(f"Failed to save rows for {file['name']}", "ERROR")
                    failed_count += 1
                if progress_callback:
                    progress = 25 + (i + 1) / len(pdf_files) * 70
                    progress_callback(int(progress))
            if progress_callback:
                progress_callback(100)
            if status_callback:
                status_callback(f"PDF workflow completed! Processed {processed_count} files, added {rows_added} rows, {failed_count} failed")
            self.log(f"PDF workflow completed. Processed {processed_count} files, added {rows_added} rows, {failed_count} failed", "SUCCESS")
            return {'success': True, 'processed': processed_count, 'rows_added': rows_added, 'failed': failed_count}
        except Exception as e:
            self.log(f"PDF workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'processed': 0, 'rows_added': 0, 'failed': 0}

def main():
    st.title("🤖 Hyperpure Automation Workflows")
    st.markdown("### Gmail to Drive & PDF to Sheet Processing")
    
    if 'automation' not in st.session_state:
        st.session_state.automation = HyperpureAutomation()
    
    if 'workflow_running' not in st.session_state:
        st.session_state.workflow_running = False
    
    automation = st.session_state.automation
    
    st.sidebar.header("Configuration")
    
    st.sidebar.subheader("🔐 Authentication")
    auth_status = st.sidebar.empty()
    
    if not automation.gmail_service or not automation.drive_service or not automation.sheets_service:
        if st.sidebar.button("🚀 Authenticate with Google", type="primary"):
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            success = automation.authenticate_from_secrets(progress_bar, status_text)
            if success:
                auth_status.success("✅ Authenticated successfully!")
                st.sidebar.success("Ready to process workflows!")
            else:
                auth_status.error("❌ Authentication failed")
            progress_bar.empty()
            status_text.empty()
    else:
        auth_status.success("✅ Already authenticated")
        if st.sidebar.button("🔄 Re-authenticate"):
            if 'oauth_token' in st.session_state:
                del st.session_state.oauth_token
            st.session_state.automation = HyperpureAutomation()
            st.rerun()
        if st.sidebar.button("🗑️ Clear Cached Token"):
            if 'oauth_token' in st.session_state:
                del st.session_state.oauth_token
            st.session_state.automation = HyperpureAutomation()
            st.success("Cached token cleared. Please re-authenticate.")
            st.rerun()
    
    tab1, tab2, tab3, tab4 = st.tabs(["📧 Mail to Drive", "📄 Drive to Sheet", "🔗 Combined Workflow", "📋 Logs & Status"])
    
    with tab1:
        st.header("📧 Mail to Drive")
        st.markdown("Download attachments from Gmail to Google Drive")
        
        if not automation.gmail_service or not automation.drive_service:
            st.warning("⚠️ Please authenticate first")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Configuration")
                st.text_input("Sender Email", value=CONFIG['gmail']['sender'], disabled=True, key="gmail_sender")
                st.text_input("Search Keywords", value=CONFIG['gmail']['search_term'], disabled=True, key="gmail_search")
                st.text_input("Google Drive Folder ID", value=CONFIG['gmail']['gdrive_folder_id'], disabled=True, key="gmail_drive_folder")
                st.text_input("Attachment Filter", value=CONFIG['gmail']['attachment_filter'], disabled=True, key="gmail_attachment_filter")
                st.subheader("Parameters")
                gmail_days_back = st.number_input("Days to search back", min_value=1, max_value=365, value=7, key="gmail_days_back")
                gmail_max_results = st.number_input("Maximum emails to process", min_value=1, max_value=500, value=50, key="gmail_max_results")
            with col2:
                st.subheader("Description")
                st.info("Downloads 'attachment.pdf' from specified emails to Drive")
            
            if st.button("🚀 Start Mail to Drive", type="primary", disabled=st.session_state.workflow_running, key="start_mail_to_drive"):
                st.session_state.workflow_running = True
                try:
                    config = {
                        'sender': CONFIG['gmail']['sender'],
                        'search_term': CONFIG['gmail']['search_term'],
                        'days_back': gmail_days_back,
                        'max_results': gmail_max_results,
                        'gdrive_folder_id': CONFIG['gmail']['gdrive_folder_id']
                    }
                    progress_container = st.container()
                    with progress_container:
                        st.subheader("📊 Processing Status")
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        def update_progress(value):
                            progress_bar.progress(value)
                        def update_status(message):
                            status_text.text(message)
                        result = automation.process_gmail_workflow(config, update_progress, update_status)
                        if result['success']:
                            st.success(f"✅ Completed! Processed {result['processed']} attachments.")
                        else:
                            st.error("❌ Failed. Check logs.")
                finally:
                    st.session_state.workflow_running = False
    
    with tab2:
        st.header("📄 Drive to Sheet")
        st.markdown("Process PDFs from Drive to Google Sheets using LlamaParse")
        
        if not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Install llama-cloud-services")
        elif not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Configuration")
                st.text_input("LlamaParse API Key", value="***HIDDEN***", disabled=True, key="pdf_llama_api")
                st.text_input("LlamaParse Agent Name", value=CONFIG['pdf']['llama_agent'], disabled=True, key="pdf_llama_agent")
                st.text_input("PDF Source Folder ID", value=CONFIG['pdf']['drive_folder_id'], disabled=True, key="pdf_drive_folder")
                st.text_input("Google Sheets Spreadsheet ID", value=CONFIG['pdf']['spreadsheet_id'], disabled=True, key="pdf_spreadsheet_id")
                st.text_input("Sheet Range", value=CONFIG['pdf']['sheet_range'], disabled=True, key="pdf_sheet_range")
                st.subheader("Parameters")
                pdf_days_back = st.number_input("Process PDFs from last N days", min_value=1, max_value=365, value=7, key="pdf_days_back")
                pdf_max_files = st.number_input("Maximum PDFs to process", min_value=1, max_value=500, value=50, key="pdf_max_files")
                pdf_skip_existing = st.checkbox("Skip already processed files", value=True, key="pdf_skip_existing")
            with col2:
                st.subheader("Description")
                st.info("Extracts data from PDFs and appends to Sheets")
            
            if st.button("🚀 Start Drive to Sheet", type="primary", disabled=st.session_state.workflow_running, key="start_drive_to_sheet"):
                st.session_state.workflow_running = True
                try:
                    config = {
                        'llama_api_key': CONFIG['pdf']['llama_api_key'],
                        'llama_agent': CONFIG['pdf']['llama_agent'],
                        'drive_folder_id': CONFIG['pdf']['drive_folder_id'],
                        'spreadsheet_id': CONFIG['pdf']['spreadsheet_id'],
                        'sheet_range': CONFIG['pdf']['sheet_range'],
                        'days_back': pdf_days_back,
                        'max_files': pdf_max_files
                    }
                    progress_container = st.container()
                    with progress_container:
                        st.subheader("📊 Processing Status")
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        def update_progress(value):
                            progress_bar.progress(value)
                        def update_status(message):
                            status_text.text(message)
                        result = automation.process_pdf_workflow(config, update_progress, update_status, pdf_skip_existing)
                        if result['success']:
                            st.success(f"✅ Completed! Processed {result['processed']} files, added {result['rows_added']} rows.")
                        else:
                            st.error("❌ Failed. Check logs.")
                finally:
                    st.session_state.workflow_running = False
    
    with tab3:
        st.header("🔗 Combined Workflow")
        st.markdown("Run Mail to Drive then Drive to Sheet (skipping existing files)")
        
        if not automation.gmail_service or not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first")
        elif not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Configuration")
                st.text_input("Gmail Sender (Combined)", value=CONFIG['gmail']['sender'], disabled=True, key="combined_gmail_sender")
                st.text_input("Gmail Search Keywords (Combined)", value=CONFIG['gmail']['search_term'], disabled=True, key="combined_gmail_search")
                st.text_input("Gmail Drive Folder ID (Combined)", value=CONFIG['gmail']['gdrive_folder_id'], disabled=True, key="combined_gmail_drive_folder")
                st.text_input("PDF LlamaParse API Key (Combined)", value="***HIDDEN***", disabled=True, key="combined_pdf_llama_api")
                st.text_input("PDF LlamaParse Agent Name (Combined)", value=CONFIG['pdf']['llama_agent'], disabled=True, key="combined_pdf_llama_agent")
                st.text_input("PDF Source Folder ID (Combined)", value=CONFIG['pdf']['drive_folder_id'], disabled=True, key="combined_pdf_drive_folder")
                st.text_input("Google Sheets Spreadsheet ID (Combined)", value=CONFIG['pdf']['spreadsheet_id'], disabled=True, key="combined_pdf_spreadsheet_id")
                st.text_input("Sheet Range (Combined)", value=CONFIG['pdf']['sheet_range'], disabled=True, key="combined_pdf_sheet_range")
                st.subheader("Parameters")
                combined_days_back = st.number_input("Days back for both", min_value=1, max_value=365, value=7, key="combined_days_back")
                combined_max_emails = st.number_input("Max emails for Gmail", min_value=1, max_value=500, value=50, key="combined_max_emails")
                combined_max_files = st.number_input("Max PDFs for processing", min_value=1, max_value=500, value=50, key="combined_max_files")
            with col2:
                st.subheader("Description")
                st.info("Runs Mail to Drive, then processes only new PDFs to Sheet")
            
            if st.button("🚀 Start Combined Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_combined_workflow"):
                st.session_state.workflow_running = True
                try:
                    gmail_config = {
                        'sender': CONFIG['gmail']['sender'],
                        'search_term': CONFIG['gmail']['search_term'],
                        'days_back': combined_days_back,
                        'max_results': combined_max_emails,
                        'gdrive_folder_id': CONFIG['gmail']['gdrive_folder_id']
                    }
                    pdf_config = {
                        'llama_api_key': CONFIG['pdf']['llama_api_key'],
                        'llama_agent': CONFIG['pdf']['llama_agent'],
                        'drive_folder_id': CONFIG['pdf']['drive_folder_id'],
                        'spreadsheet_id': CONFIG['pdf']['spreadsheet_id'],
                        'sheet_range': CONFIG['pdf']['sheet_range'],
                        'days_back': combined_days_back,
                        'max_files': combined_max_files
                    }
                    progress_container = st.container()
                    with progress_container:
                        st.subheader("📊 Processing Status")
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        def update_progress(value):
                            progress_bar.progress(value)
                        def update_status(message):
                            status_text.text(message)
                        update_status("Running Mail to Drive...")
                        gmail_result = automation.process_gmail_workflow(gmail_config, update_progress, update_status)
                        if not gmail_result['success']:
                            st.error("❌ Mail to Drive failed.")
                            st.session_state.workflow_running = False
                            return
                        update_status("Running Drive to Sheet on new files...")
                        pdf_result = automation.process_pdf_workflow(pdf_config, update_progress, update_status, skip_existing=True)
                        if pdf_result['success']:
                            summary = f"✅ Completed!\nGmail: Processed {gmail_result['processed']} attachments\nPDF: Processed {pdf_result['processed']} new files, added {pdf_result['rows_added']} rows"
                            st.success(summary)
                        else:
                            st.error("❌ Drive to Sheet failed.")
                finally:
                    st.session_state.workflow_running = False
    
    with tab4:
        st.header("📋 System Logs & Status")
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔄 Refresh Logs", key="refresh_logs"):
                st.rerun()
        with col2:
            if st.button("🗑️ Clear Logs", key="clear_logs"):
                automation.clear_logs()
                st.success("Logs cleared!")
                st.rerun()
        with col3:
            if st.checkbox("Auto-refresh (5s)", value=False, key="auto_refresh"):
                time.sleep(5)
                st.rerun()
        logs = automation.get_logs()
        if logs:
            st.subheader(f"Recent Activity ({len(logs)} entries)")
            for log_entry in reversed(logs[-50:]):
                timestamp = log_entry['timestamp']
                level = log_entry['level']
                message = log_entry['message']
                if level == "ERROR":
                    st.error(f"🔴 **{timestamp}** - {message}")
                elif level == "WARNING":
                    st.warning(f"🟡 **{timestamp}** - {message}")
                elif level == "SUCCESS":
                    st.success(f"🟢 **{timestamp}** - {message}")
                elif level == "DEBUG":
                    st.info(f"🐞 **{timestamp}** - {message}")
                else:
                    st.info(f"ℹ️ **{timestamp}** - {message}")
        else:
            st.info("No logs available.")
        st.subheader("🔧 System Status")
        status_cols = st.columns(2)
        with status_cols[0]:
            st.metric("Authentication Status", "✅ Connected" if automation.gmail_service else "❌ Not Connected")
            st.metric("Workflow Status", "🟡 Running" if st.session_state.workflow_running else "🟢 Idle")
        with status_cols[1]:
            st.metric("LlamaParse Available", "✅ Available" if LLAMA_AVAILABLE else "❌ Not Installed")
            st.metric("Total Logs", len(logs))

if __name__ == "__main__":
    main()
