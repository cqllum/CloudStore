import json
import os
from abc import ABC, abstractmethod

class CloudBroker(ABC):
    """Abstract base class for cloud storage brokers"""
    
    def __init__(self, config):
        self.config = config
    
    @abstractmethod
    def upload_file(self, file_data, filename):
        pass
    
    @abstractmethod
    def download_file(self, storage_path):
        pass
    
    @abstractmethod
    def delete_file(self, storage_path):
        pass
    
    @abstractmethod
    def list_files(self, path=''):
        pass
    
    @abstractmethod
    def get_storage_info(self):
        """Return storage info: {'total': bytes, 'used': bytes, 'available': bytes}"""
        pass

class LocalBroker(CloudBroker):
    """Local filesystem broker"""
    
    def upload_file(self, file_data, filename):
        storage_dir = self.config.get('path', 'storage/local')
        os.makedirs(storage_dir, exist_ok=True)
        file_path = os.path.join(storage_dir, filename)
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
        return file_path
    
    def download_file(self, storage_path):
        # Use storage_path as-is since it's already the full path from upload
        if not os.path.exists(storage_path):
            raise FileNotFoundError(f'File not found: {storage_path}')
        
        with open(storage_path, 'rb') as f:
            return f.read()
    
    def delete_file(self, storage_path):
        if not os.path.isabs(storage_path):
            storage_dir = self.config.get('path', 'storage/local')
            storage_path = os.path.join(storage_dir, storage_path)
        os.remove(storage_path)
    
    def list_files(self, path=''):
        storage_dir = self.config.get('path', 'storage/local')
        full_path = os.path.join(storage_dir, path) if path else storage_dir
        
        if not os.path.exists(full_path):
            return []
        
        items = []
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            items.append({
                'name': item,
                'type': 'folder' if os.path.isdir(item_path) else 'file',
                'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0
            })
        return items
    
    def get_storage_info(self):
        import shutil
        storage_dir = self.config.get('path', 'storage/local')
        os.makedirs(storage_dir, exist_ok=True)
        
        # Get disk usage for the entire disk
        total, disk_used, free = shutil.disk_usage(storage_dir)
        
        # Calculate actual used space only in our storage directory
        actual_used = 0
        try:
            for root, dirs, files in os.walk(storage_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.exists(file_path):
                        actual_used += os.path.getsize(file_path)
        except Exception as e:
            print(f"Error calculating storage usage: {e}")
            actual_used = 0
        
        return {
            'total': total,
            'used': actual_used,  # Only files in our storage directory
            'available': free
        }

class S3Broker(CloudBroker):
    """AWS S3 broker - placeholder for implementation"""
    
    def upload_file(self, file_data, filename):
        # Implement boto3 S3 upload
        bucket = self.config.get('bucket')
        # boto3 implementation here
        return f"s3://{bucket}/{filename}"
    
    def download_file(self, storage_path):
        # Implement boto3 S3 download
        pass
    
    def delete_file(self, storage_path):
        # Implement boto3 S3 delete
        pass
    
    def list_files(self, path=''):
        # Implement S3 list objects
        return []
    
    def get_storage_info(self):
        # S3 doesn't have storage limits in traditional sense
        return {
            'total': float('inf'),
            'used': 0,
            'available': float('inf')
        }

class MegaBroker(CloudBroker):
    """Mega.io storage broker"""
    
    def __init__(self, config):
        super().__init__(config)
        from mega import Mega
        self.mega = Mega()
        self.m = self.mega.login(config['email'], config['password'])
    
    def upload_file(self, file_data, filename):
        import tempfile
        import os
        
        # Create temp file with the full filename (preserving folder structure)
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, filename.replace('/', '_'))
        
        try:
            with open(temp_path, 'wb') as f:
                f.write(file_data)
            
            # Upload to Mega with original filename structure
            file_node = self.m.upload(temp_path)
            return filename
        except Exception as e:
            raise Exception(f"Mega upload failed: {str(e)}")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
    
    def download_file(self, storage_path):
        try:
            # Use find method to locate file
            file_node = self.m.find(storage_path)
            if file_node:
                # Download to temporary directory
                import tempfile
                import os
                
                temp_dir = tempfile.mkdtemp()
                try:
                    # Download returns the path to downloaded file
                    downloaded_file = self.m.download(file_node, temp_dir)
                    with open(downloaded_file, 'rb') as f:
                        content = f.read()
                    return content
                finally:
                    # Clean up downloaded file and temp dir
                    for file in os.listdir(temp_dir):
                        os.unlink(os.path.join(temp_dir, file))
                    os.rmdir(temp_dir)
            else:
                raise FileNotFoundError(f'File not found in Mega: {storage_path}')
        except Exception as e:
            raise Exception(f'Mega download failed: {str(e)}')
    
    def delete_file(self, storage_path):
        file_node = self.m.find(storage_path)
        if file_node:
            self.m.delete(file_node[0])
    
    def list_files(self, path=''):
        try:
            files = self.m.get_files()
            items = []
            for file_info in files.values():
                if file_info.get('a') and file_info['a'].get('n'):
                    items.append({
                        'name': file_info['a']['n'],
                        'type': 'folder' if file_info.get('t') == 1 else 'file',
                        'size': file_info.get('s', 0)
                    })
            return items
        except Exception:
            return []
    
    def get_storage_info(self):
        try:
            quota = self.m.get_quota()
            return {
                'total': quota,
                'used': self.m.get_storage_space(files=self.m.get_files()),
                'available': quota - self.m.get_storage_space(files=self.m.get_files())
            }
        except Exception:
            # Default Mega free account: 20GB
            return {
                'total': 20 * 1024 * 1024 * 1024,
                'used': 0,
                'available': 20 * 1024 * 1024 * 1024
            }

class DropboxBroker(CloudBroker):
    """Dropbox storage broker"""
    
    def __init__(self, config):
        super().__init__(config)
        import dropbox
        self.dbx = dropbox.Dropbox(config['access_token'])
    
    def upload_file(self, file_data, filename):
        import dropbox
        try:
            # Keep the full path with account_id folder
            path = f'/{filename}'
            self.dbx.files_upload(file_data, path, mode=dropbox.files.WriteMode.overwrite)
            return filename
        except Exception as e:
            raise Exception(f"Dropbox upload failed: {str(e)}")
    
    def download_file(self, storage_path):
        try:
            # Handle empty or root paths
            if not storage_path or storage_path == '/':
                raise Exception('Invalid storage path')
            
            # Ensure path starts with / and is properly formatted
            path = f'/{storage_path}' if not storage_path.startswith('/') else storage_path
            
            _, response = self.dbx.files_download(path)
            return response.content
        except Exception as e:
            raise Exception(f'Dropbox download failed for path "{storage_path}": {str(e)}')
    
    def delete_file(self, storage_path):
        try:
            path = f'/{storage_path}' if not storage_path.startswith('/') else storage_path
            self.dbx.files_delete_v2(path)
        except Exception as e:
            raise Exception(f'Dropbox delete failed: {str(e)}')
    
    def list_files(self, path=''):
        try:
            folder_path = f'/{path}' if path and not path.startswith('/') else (path or '')
            result = self.dbx.files_list_folder(folder_path)
            items = []
            for entry in result.entries:
                import dropbox
                items.append({
                    'name': entry.name,
                    'type': 'folder' if isinstance(entry, dropbox.files.FolderMetadata) else 'file',
                    'size': entry.size if hasattr(entry, 'size') else 0
                })
            return items
        except Exception:
            return []
    
    def get_storage_info(self):
        try:
            usage = self.dbx.users_get_space_usage()
            return {
                'total': usage.allocation.get_individual().allocated,
                'used': usage.used,
                'available': usage.allocation.get_individual().allocated - usage.used
            }
        except Exception:
            # Default Dropbox free account: 2GB
            return {
                'total': 2 * 1024 * 1024 * 1024,
                'used': 0,
                'available': 2 * 1024 * 1024 * 1024
            }

class GCPBroker(CloudBroker):
    """Google Cloud Storage broker - placeholder"""
    
    def upload_file(self, file_data, filename):
        # Implement GCP storage upload
        pass
    
    def download_file(self, storage_path):
        pass
    
    def delete_file(self, storage_path):
        pass
    
    def list_files(self, path=''):
        # Implement GCP storage list
        return []
    
    def get_storage_info(self):
        # GCP doesn't have storage limits in traditional sense
        return {
            'total': float('inf'),
            'used': 0,
            'available': float('inf')
        }

def get_broker(broker_type, config):
    """Factory function to get appropriate broker"""
    brokers = {
        'local': LocalBroker,
        's3': S3Broker,
        'gcp': GCPBroker,
        'mega': MegaBroker,
        'dropbox': DropboxBroker
    }
    
    broker_class = brokers.get(broker_type, LocalBroker)
    return broker_class(config)