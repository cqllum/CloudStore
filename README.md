<img src="https://i.imgur.com/7rFn1Ab.png">

# CloudStore - Decentralized File Storage System

> **🚧 Work in Progress** - This project is actively being developed and improved.

A Flask-based distributed file storage system that provides a unified interface for storing files across multiple cloud providers and storage nodes with automatic replication and load balancing.

## Features

- **Multi-Cloud Storage** - Support for Local, Mega.io, Dropbox, AWS S3, and Google Cloud Storage
- **Automatic Replication** - Configurable file replication across multiple storage brokers (this can be replicated in settings)
- **Smart Load Balancing** - Intelligent file distribution based on broker usage and availability
- **User Management** - Complete authentication system with admin controls
- **Virtual File System** - Hierarchical directory structure with folder management
- **Real-time Monitoring** - Storage usage tracking and broker health monitoring
- **Web Interface** - Modern responsive UI for file management
- **RESTful API** - Complete API for programmatic access
- **Whitelabel Support** - Customizable branding and themes

## Installation Guide

### Prerequisites
- Python 3.7 or higher
- pip package manager
- Git (for cloning)

### Step-by-Step Installation

1. **Clone the repository**:
```bash
git clone https://github.com/cqllum/Cloudstore
cd Cloudstore
```

2. **Create virtual environment** (recommended):
```bash
python -m venv cloudstore-env

# On Windows:
cloudstore-env\Scripts\activate

# On macOS/Linux:
source cloudstore-env/bin/activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure environment**:
```bash
cp .env.example .env
```

Edit `.env` file with your settings:
```bash
SECRET_KEY=your-unique-secret-key-here
PORT=5000
DEBUG=False
```

5. **Initialize the database**:
```bash
python app.py
```
The application will automatically create the SQLite database and default admin user.

6. **Access the application**:
   - Open browser: http://localhost:5000
   - Login with: `admin/admin`
   - Change default password immediately

### First-Time Setup

1. **Login as admin** and change the default password
2. **Add storage brokers** (Local storage is created automatically)
3. **Create regular users** if needed
4. **Configure system settings** (replication, themes, etc.)

### Production Deployment

1. **Set environment variables**:
```bash
export SECRET_KEY="your-production-secret-key"
export DEBUG=False
export PORT=5000
```

2. **Use production WSGI server**:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

3. **Set up reverse proxy** (nginx recommended)
4. **Configure SSL/TLS** for HTTPS
5. **Set up regular backups** of the SQLite database

## Dashboard Pages Overview

### Login Page (`/`)
Login/registration
<img src="https://i.imgur.com/r44PzvK.png">


### User Dashboard (`/dashboard`)
The main file management interface for regular users:
<img src="https://i.imgur.com/GcYS2Mm.png">


**Features:**
- **File Grid/List/Detail Views** - Switch between different file display modes
- **Upload Files** - Drag-and-drop or browse to upload files
- **Create Files/Folders** - Built-in text editor for creating new files
- **Search Functionality** - Find files across your storage
- **File Operations** - Download, rename, move, copy, delete files
- **Breadcrumb Navigation** - Easy folder navigation
- **Storage Usage** - Real-time storage quota tracking
- **Upload Queue** - Monitor file upload progress
- **Drag & Drop** - Move files between folders
- **Context Menus** - Right-click for quick actions
- **File Metadata** - View file details and replica locations


### Admin Panel (`/admin`)
Comprehensive administration interface:
<img src="https://i.imgur.com/nM4dyJ8.png">

**User Management:**
- Create, edit, and delete user accounts
- Set admin privileges
- View user storage usage and file counts
- Browse individual user files
- Reset user passwords

**System Monitoring:**
- Real-time broker status monitoring
- Storage usage across all brokers
- System health indicators
- Background task monitoring

### Storage Browser (`/browse`)
Direct storage broker management (Admin only):
<img src="https://i.imgur.com/Yn601d8.png">

**Features:**
- Browse raw storage on each broker
- View actual files stored on cloud providers
- Delete orphaned files
- Monitor broker connectivity
- Inspect storage paths and file distribution

### Broker Management (`/manage`)
Storage provider configuration (Admin only):
<img src="https://i.imgur.com/FsT8RY2.png">
<img src="https://i.imgur.com/UmCTSex.png">

**Broker Operations:**
- Add new storage brokers (Local, Mega, Dropbox, S3, GCP)
- Edit broker credentials and settings
- Enable/disable brokers
- Test broker connectivity
- View broker storage statistics
- Remove unused brokers

### Storage Space Monitor (`/storage_space`)
Detailed storage analytics (Admin only):
<img src="https://i.imgur.com/uvlRV18.png">

**Analytics:**
- Total storage across all brokers
- Virtual vs actual storage usage
- Per-broker utilization charts
- Storage efficiency metrics
- Replication overhead analysis

### Admin Settings (`/admin/settings_page`)
System configuration interface:
<img src="https://i.imgur.com/wsyDPvx.png">

**System Settings:**
- Replication count (how many copies of each file)
- Broker refresh interval (health check frequency)
- Storage quotas per user

**Whitelabel Customization:**
- Site name and branding
- Custom CSS styling
- Color scheme configuration
- Theme presets
- Logo and favicon upload

### User File Viewer (`/admin/user_files_view/<user_id>`)
Admin view of individual user files:
<img src="https://i.imgur.com/uJYOJ4H.png">

**File Management:**
- View all files for specific user
- See file replica locations
- Delete user files
- Monitor user storage patterns
- Troubleshoot file access issues

## Configuration

### Environment Variables
```bash
SECRET_KEY=your-secret-key-here
PORT=5000
DEBUG=False
```

### Storage Brokers

#### Local Storage
```json
{
  "name": "Local Storage",
  "type": "local",
  "config": {
    "path": "storage/local"
  }
}
```

#### Mega.io
```json
{
  "name": "Mega Storage",
  "type": "mega",
  "config": {
    "email": "your-email@example.com",
    "password": "your-password"
  }
}
```

#### Dropbox
```json
{
  "name": "Dropbox",
  "type": "dropbox",
  "config": {
    "access_token": "your-dropbox-access-token"
  }
}
```

## API Reference

### Authentication
```bash
# Register user
POST /register
{
  "username": "user",
  "password": "password"
}

# Login
POST /login
{
  "username": "user",
  "password": "password"
}
```

### Storage Management
```bash
# Add storage broker
POST /add_broker
{
  "name": "My Storage",
  "type": "local",
  "config": {"path": "/storage"}
}

# Upload file
POST /upload
Content-Type: multipart/form-data
file: <file-data>
virtual_path: "/documents/"

# Download file
GET /download_file?filename=document.pdf&path=/documents/

# Search files
GET /search?q=document&path=/documents/

# List files
GET /files?path=/documents/
```

### File Operations
```bash
# Create folder
POST /create_folder
{
  "path": "/new-folder/"
}

# Rename file
POST /rename_file
{
  "old_name": "old.txt",
  "new_name": "new.txt",
  "virtual_path": "/"
}

# Delete file
DELETE /delete_file
{
  "filename": "document.pdf",
  "virtual_path": "/documents/"
}

# Move file
POST /move_file
{
  "filename": "document.pdf",
  "old_path": "/documents/",
  "new_path": "/archive/"
}
```

## Architecture

### System Components
1. **Flask Web Server** - HTTP API and web interface
2. **SQLite Database** - Metadata storage and user management
3. **Storage Brokers** - Pluggable cloud storage adapters
4. **Replication Engine** - Automatic file distribution and redundancy
5. **Background Workers** - Broker health monitoring and maintenance

### Database Schema
- **users** - User accounts and authentication
- **brokers** - Storage provider configurations
- **files** - File metadata and virtual paths
- **file_replicas** - File location tracking across brokers
- **settings** - System configuration

### Storage Flow
1. File uploaded via API/UI
2. System selects optimal brokers based on load balancing
3. File replicated across configured number of brokers
4. Metadata stored in database with replica locations
5. Background workers monitor broker health

## Administration

### Admin Features
- User management (create, edit, delete users)
- Storage broker configuration
- System settings (replication count, refresh intervals)
- Storage usage monitoring
- Theme customization

### System Settings
- **Replica Count**: Number of copies per file (default: 2)
- **Broker Refresh**: Health check interval in minutes (default: 5)
- **Storage Limit**: Per-user storage quota (default: 5GB)

## Development

### Adding New Storage Brokers

1. **Implement CloudBroker interface**:
```python
class CustomBroker(CloudBroker):
    def upload_file(self, file_data, filename):
        # Upload implementation
        return storage_path
    
    def download_file(self, storage_path):
        # Download implementation
        return file_data
    
    def delete_file(self, storage_path):
        # Delete implementation
        pass
    
    def list_files(self, path=''):
        # List implementation
        return file_list
    
    def get_storage_info(self):
        # Storage info implementation
        return {'total': 0, 'used': 0, 'available': 0}
```

2. **Register in broker factory**:
```python
# In cloud_brokers.py
brokers = {
    'local': LocalBroker,
    'custom': CustomBroker,
    # ...
}
```
 

## Security

- Password hashing 
- Session-based authentication
- File access control per user
- Admin privilege separation
- Secure file upload handling

## Limitations

- 5GB storage limit per user (configurable)
- SQLite database (suitable for small-medium deployments)
- No end-to-end encryption (files stored as-is on brokers)
- Limited concurrent user support

FYI - currently this is a POC / beta product - encryption should be added and better distribution of secured areas on brokers should be introduced.
This shouldn't be used for anything sensitive, merely just a way to remove clutter on your own storage areas.

This goal here is to have a whitelabel solution that can be integrated into your own platforms (i.e hosting companies) and have sufficient user management whilst having good security practices.
I will continue to work on this over time but feel free to contribute, and also raise issues where you have a problem.

Also note that the architecture here (specifiaclly SQLite was to demonstrate and build the product quickly - production environments should and will not be using this on the release of that..)


## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

 
  
