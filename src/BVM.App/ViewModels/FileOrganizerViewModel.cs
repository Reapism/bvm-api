using BVM.App.Models;
using BVM.App.Services;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace BVM.App.ViewModels
{
    public class FileOrganizerViewModel : INotifyPropertyChanged
    {
        private readonly FileOrganizerService _service = new();
        private CancellationTokenSource? _cts;

        public string SourceDirectory { get; set; } = "";
        public string DestinationDirectory { get; set; } = "";
        public ObservableCollection<FileMetadata> Files { get; } = new();

        private int _progress;
        public int Progress
        {
            get => _progress;
            set { _progress = value; OnPropertyChanged(); }
        }

        public bool IsBusy => _cts != null;

        // Commands
        public IAsyncRelayCommand ScanCommand { get; }
        public ICommand PreviewCommand { get; }
        public IAsyncRelayCommand OrganizeCommand { get; }
        public IAsyncRelayCommand RevertCommand { get; }
        public ICommand BrowseSourceCommand { get; }
        public ICommand BrowseDestinationCommand { get; }

        public FileOrganizerViewModel()
        {
            // correct canExecute: !IsBusy
            ScanCommand = new AsyncRelayCommand(DoScan, () => !IsBusy);
            PreviewCommand = new RelayCommand(DoPreview, () => Files.Any() && !IsBusy);
            OrganizeCommand = new AsyncRelayCommand(DoOrganize, () => Files.Any() && !IsBusy);
            RevertCommand = new AsyncRelayCommand(DoRevert, () => !IsBusy);

            BrowseSourceCommand = new RelayCommand(DoBrowseSource, () => !IsBusy);
            BrowseDestinationCommand = new RelayCommand(DoBrowseDestination, () => !IsBusy);

            // when the file list changes, re-check Preview & Organize
            Files.CollectionChanged += (_, __) => UpdateCommands();
        }

        private void UpdateCommands()
        {
            ScanCommand.NotifyCanExecuteChanged();
            PreviewCommand.As<RelayCommand>()?.NotifyCanExecuteChanged();
            OrganizeCommand.NotifyCanExecuteChanged();
            RevertCommand.NotifyCanExecuteChanged();
            BrowseSourceCommand.As<RelayCommand>()?.NotifyCanExecuteChanged();
            BrowseDestinationCommand.As<RelayCommand>()?.NotifyCanExecuteChanged();
        }

        private void SetBusy(bool busy)
        {
            if (busy) _cts = new CancellationTokenSource();
            else _cts?.Dispose();
            if (!busy) _cts = null;

            OnPropertyChanged(nameof(IsBusy));
            UpdateCommands();
        }

        private async Task DoScan()
        {
            SetBusy(true);
            try
            {
                Files.Clear();
                var req = new FileOrganizerRequest
                {
                    SourceDirectory = SourceDirectory,
                    DestinationDirectory = DestinationDirectory
                };

                var list = await _service.ScanAsync(
                    req,
                    new Progress<int>(p => Progress = p),
                    _cts!.Token);

                foreach (var f in list)
                    Files.Add(f);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void DoPreview()
        {
            foreach (var f in Files)
                f.DestinationPath = Path.Combine(
                    DestinationDirectory,
                    f.Year.ToString(),
                    f.FileName);

            // if you want the grid to refresh
            OnPropertyChanged(nameof(Files));
        }

        private async Task DoOrganize()
        {
            SetBusy(true);
            try
            {
                var req = new FileOrganizerRequest
                {
                    SourceDirectory = SourceDirectory,
                    DestinationDirectory = DestinationDirectory,
                    Files = Files.ToList()
                };

                await _service.OrganizeAsync(
                    req,
                    new Progress<int>(p => Progress = p),
                    _cts!.Token);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async Task DoRevert()
        {
            SetBusy(true);
            try
            {
                var dlg = new OpenFileDialog
                {
                    Filter = "JSON log|move-log.json",
                    InitialDirectory = DestinationDirectory
                };
                if (dlg.ShowDialog() != true) return;

                Files.Clear();
                var list = await _service.LoadFromLogAsync(dlg.FileName);
                foreach (var f in list)
                    Files.Add(f);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void DoBrowseSource()
        {
            // use OpenFileDialog as a folder-picker
            var dlg = new OpenFolderDialog
            {
                Title = "Select source folder",
                ValidateNames = false,
            };
            if (dlg.ShowDialog() == true)
            {
                SourceDirectory = dlg.FolderName;
                OnPropertyChanged(nameof(SourceDirectory));
                UpdateCommands();
            }
        }

        private void DoBrowseDestination()
        {
            var dlg = new OpenFolderDialog
            {
                Title = "Select destination folder",
                ValidateNames = false,
            };
            if (dlg.ShowDialog() == true)
            {
                DestinationDirectory = dlg.FolderName;
                OnPropertyChanged(nameof(DestinationDirectory));
                UpdateCommands();
            }
        }


        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    static class CmdExt
    {
        public static T? As<T>(this object? o) where T : class => o as T;
    }
}
