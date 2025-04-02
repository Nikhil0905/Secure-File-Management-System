import click
import os
from secure_file_manager import SecureFileManager
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from datetime import datetime
import sys

console = Console()

def handle_error(func):
    """Decorator to handle errors gracefully"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            sys.exit(1)
    return wrapper

@click.group()
def cli():
    """Secure File Management System"""
    pass

@cli.command(name='register')
@click.argument('username')
@click.password_option()
@handle_error
def register(username, password):
    """Register a new user"""
    file_manager = SecureFileManager()
    if file_manager.register_user(username, password):
        console.print(f"[green]User {username} registered successfully![/green]")
        console.print("[yellow]Please save your 2FA backup code shown above.[/yellow]")
    else:
        console.print("[red]Registration failed. Username might already exist.[/red]")

@cli.command(name='login')
@click.argument('username')
@handle_error
def login(username: str):
    """Login to the system (2FA required)"""
    # Get password securely
    password = click.prompt('Password', type=str, hide_input=True)
    
    # Try to login
    file_manager = SecureFileManager()
    
    # First attempt login with password
    if file_manager.verify_password(username, password):
        # Always require 2FA
        code = click.prompt('Enter 2FA code from your authenticator app', type=str)
        if file_manager.verify_2fa(username, code):
            file_manager.complete_login(username)
            console.print("[green]Login successful![/green]")
        else:
            console.print("[red]Invalid 2FA code. Login failed.[/red]")
    else:
        console.print("[red]Login failed. Please check your credentials.[/red]")

@cli.command(name='status')
@handle_error
def status():
    """Check login status"""
    file_manager = SecureFileManager()
    if file_manager.current_user:
        console.print(f"[green]Logged in as {file_manager.current_user}[/green]")
    else:
        console.print("[red]Not logged in[/red]")

@cli.command(name='upload')
@click.argument('file_path', type=click.Path(exists=True))
@handle_error
def upload(file_path):
    """Upload a file"""
    file_manager = SecureFileManager()
    if not file_manager.current_user:
        console.print("[red]Please login first[/red]")
        return
    
    success, message = file_manager.upload_file(file_path)
    if success:
        console.print(f"[green]File uploaded successfully![/green]")
    else:
        console.print(f"[red]Upload failed: {message}[/red]")

@cli.command(name='download')
@click.argument('filename')
@click.argument('save_path')
@handle_error
def download(filename, save_path):
    """Download a file from secure storage"""
    file_manager = SecureFileManager()
    if not file_manager.is_logged_in():
        console.print("[red]Please login first[/red]")
        return
    
    result = file_manager.download_file(filename, save_path)
    if result:
        console.print(f"[green]Successfully downloaded {filename} to {save_path}[/green]")
    else:
        console.print(f"[red]Error: Failed to download file[/red]")

@cli.command(name='list')
@handle_error
def list():
    """List all files"""
    file_manager = SecureFileManager()
    if not file_manager.current_user:
        console.print("[red]Please login first[/red]")
        return
    
    files = file_manager.list_files()
    if not files:
        console.print("[yellow]No files found[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("S.No", style="bold", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Type", style="green")
    table.add_column("Uploaded", style="yellow")
    table.add_column("Owner", style="blue")
    table.add_column("Shared", style="red")
    
    for index, file_info in enumerate(files, 1):
        table.add_row(
            str(index),
            file_info['name'],
            file_info['size'],
            file_info['file_type'],
            file_info['uploaded_at'],
            file_info['owner'],
            ", ".join(file_info['shared_with']) if file_info['shared_with'] else "No"
        )
    
    console.print(table)

@cli.command(name='share')
@click.argument('filename')
@click.argument('target_user')
@handle_error
def share(filename: str, target_user: str):
    """Share a file with another user"""
    file_manager = SecureFileManager()
    if file_manager.share_file(filename, target_user):
        console.print(f"[green]File '{filename}' shared with {target_user}[/green]")
    else:
        console.print("[red]Failed to share file. Please check if the file exists and you have permission.[/red]")

@cli.command(name='delete')
@click.argument('filename')
@handle_error
def delete(filename):
    """Delete a file"""
    file_manager = SecureFileManager()
    if not file_manager.current_user:
        console.print("[red]Please login first[/red]")
        return
    
    if file_manager.delete_file(filename):
        console.print(f"[green]File '{filename}' deleted successfully![/green]")
    else:
        console.print(f"[red]Failed to delete file. Please check if the file exists and you have permission.[/red]")

@cli.command(name='logout')
@handle_error
def logout():
    """Logout from the system"""
    file_manager = SecureFileManager()
    if file_manager.current_user:
        file_manager.logout()
        console.print("[green]Logged out successfully[/green]")
    else:
        console.print("[yellow]Not logged in[/yellow]")

if __name__ == '__main__':
    cli() 
