import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from secure_file_manager import SecureFileManager
import os
from datetime import datetime
from pathlib import Path

console = Console()
file_manager = SecureFileManager()

def check_auth():
    if not file_manager.current_user:
        console.print(Panel(Text("You must be logged in to perform this action", style="red")))
        return False
    return True

def format_size(size_bytes: int) -> str:
    """Convert size in bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"

def validate_path(path: str) -> Path:
    """Validate and normalize file path"""
    try:
        # Convert to Path object
        path_obj = Path(path)
        # Resolve to absolute path
        abs_path = path_obj.resolve()
        return abs_path
    except Exception as e:
        raise click.BadParameter(f"Invalid path: {str(e)}")

@click.group()
def cli():
    """Secure File Management System CLI"""
    pass

@cli.command()
def status():
    """Check current login status"""
    if file_manager.current_user:
        console.print(Panel(Text(f"Currently logged in as: {file_manager.current_user}", style="green")))
    else:
        console.print(Panel(Text("Not logged in", style="yellow")))

@cli.command()
@click.argument('username')
@click.password_option()
def register(username, password):
    """Register a new user"""
    if file_manager.current_user:
        console.print(Panel(Text("Please logout before registering a new user", style="red")))
        return

    if file_manager.register_user(username, password):
        console.print(Panel(Text(f"Successfully registered user: {username}", style="green")))
    else:
        console.print(Panel(Text("Error: Username already exists", style="red")))

@cli.command()
@click.argument('username')
def login(username):
    """Login to the system"""
    if file_manager.current_user:
        console.print(Panel(Text(f"Already logged in as: {file_manager.current_user}. Please logout first.", style="yellow")))
        return

    password = click.prompt('Password', type=str, hide_input=True)
    if file_manager.login(username, password):
        console.print(Panel(Text(f"Successfully logged in as: {username}", style="green")))
    else:
        console.print(Panel(Text("Error: Invalid username or password", style="red")))

@cli.command()
def logout():
    """Logout from the system"""
    if not file_manager.current_user:
        console.print(Panel(Text("Not logged in", style="yellow")))
        return

    file_manager.logout()
    console.print(Panel(Text("Successfully logged out", style="green")))

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
def upload(file_path):
    """Upload a file to the secure storage"""
    if check_auth():
        try:
            # Validate and normalize the path
            normalized_path = validate_path(file_path)
            
            # Check if path is a file
            if not normalized_path.is_file():
                console.print(Panel(Text(f"Error: {file_path} is not a file", style="red")))
                return

            # Check file permissions
            try:
                with open(normalized_path, 'rb') as f:
                    f.seek(0)
                    f.read(1)
                    f.seek(0)
            except PermissionError:
                console.print(Panel(Text(f"Error: Permission denied for {file_path}", style="red")))
                return
            except Exception as e:
                console.print(Panel(Text(f"Error accessing file: {str(e)}", style="red")))
                return

            if file_manager.upload_file(str(normalized_path)):
                console.print(Panel(Text(f"Successfully uploaded: {file_path}", style="green")))
            else:
                console.print(Panel(Text("Error: Failed to upload file. Check the logs for details.", style="red")))
        except click.BadParameter as e:
            console.print(Panel(Text(str(e), style="red")))
        except Exception as e:
            console.print(Panel(Text(f"An unexpected error occurred: {str(e)}", style="red")))

@cli.command()
@click.argument('filename')
@click.argument('output_path', type=click.Path())
def download(filename, output_path):
    """Download a file from secure storage"""
    if check_auth():
        try:
            # Validate and normalize the output path
            normalized_output = validate_path(output_path)
            
            # Check if output directory exists and is writable
            output_dir = normalized_output.parent
            if not output_dir.exists():
                try:
                    output_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    console.print(Panel(Text(f"Error creating output directory: {str(e)}", style="red")))
                    return

            # Check if output location is writable
            try:
                with open(normalized_output, 'wb') as f:
                    f.write(b'')
                os.remove(normalized_output)
            except PermissionError:
                console.print(Panel(Text(f"Error: Permission denied for output location: {output_path}", style="red")))
                return
            except Exception as e:
                console.print(Panel(Text(f"Error checking output location: {str(e)}", style="red")))
                return

            file_data = file_manager.download_file(filename)
            if file_data:
                try:
                    with open(normalized_output, 'wb') as f:
                        f.write(file_data)
                    console.print(Panel(Text(f"Successfully downloaded: {filename}", style="green")))
                except Exception as e:
                    console.print(Panel(Text(f"Error saving file: {str(e)}", style="red")))
            else:
                console.print(Panel(Text("Error: File not found or access denied", style="red")))
        except click.BadParameter as e:
            console.print(Panel(Text(str(e), style="red")))
        except Exception as e:
            console.print(Panel(Text(f"An unexpected error occurred: {str(e)}", style="red")))

@cli.command()
def list():
    """List all files in secure storage"""
    if check_auth():
        files = file_manager.list_files()
        if files:
            table = Table(title="Your Files")
            table.add_column("S.No.", style="bold white", justify="right")
            table.add_column("Filename", style="cyan")
            table.add_column("Size", style="magenta")
            table.add_column("Uploaded At", style="yellow")
            table.add_column("Owner", style="green")
            table.add_column("Status", style="blue")
            
            for index, file_info in enumerate(files, 1):
                uploaded_at = datetime.fromisoformat(file_info['uploaded_at']).strftime('%Y-%m-%d %H:%M:%S')
                status = "Shared" if file_info.get('shared', False) else "Owned"
                table.add_row(
                    str(index),
                    file_info['name'],
                    format_size(file_info['size']),
                    uploaded_at,
                    file_info['owner'],
                    status
                )
            console.print(table)
        else:
            console.print(Panel(Text("No files found", style="yellow")))

@cli.command()
@click.argument('filename')
def delete(filename):
    """Delete a file from secure storage"""
    if check_auth():
        if file_manager.delete_file(filename):
            console.print(Panel(Text(f"Successfully deleted: {filename}", style="green")))
        else:
            console.print(Panel(Text("Error: File not found or access denied", style="red")))

@cli.command()
@click.argument('filename')
@click.argument('username')
def share(filename, username):
    """Share a file with another user"""
    if check_auth():
        if file_manager.share_file(filename, username):
            console.print(Panel(Text(f"Successfully shared {filename} with {username}", style="green")))
        else:
            console.print(Panel(Text("Error: Failed to share file. Check the logs for details.", style="red")))

@cli.command()
@click.argument('filename')
@click.argument('username')
def revoke(filename, username):
    """Revoke file sharing with another user"""
    if check_auth():
        if file_manager.revoke_share(filename, username):
            console.print(Panel(Text(f"Successfully revoked sharing of {filename} with {username}", style="green")))
        else:
            console.print(Panel(Text("Error: Failed to revoke file sharing. Check the logs for details.", style="red")))

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\nOperation cancelled by user")
    except Exception as e:
        console.print(Panel(Text(f"An unexpected error occurred: {str(e)}", style="red"))) 