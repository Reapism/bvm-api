using BVM.App.Models;
using System.IO;
using System.Text.Json;

namespace BVM.App.Services
{
    public class FileOrganizerService
    {
        public static string GetRelativePathFromDirectory(string sourceDir, string targetPath)
        {
            return Path.GetRelativePath(sourceDir, targetPath)
                                   .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        public async Task<List<FileMetadata>> ScanAsync(
            FileOrganizerRequest req,
            IProgress<int>? progress = null,
            CancellationToken ct = default)
        {
            var files = new List<FileMetadata>();
            var allFiles = Directory
                .EnumerateFiles(req.SourceDirectory, "*.*", SearchOption.AllDirectories)
                .ToList();

            int total = allFiles.Count, processed = 0;
            foreach (var path in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                var info = new FileInfo(path);
                var relative = GetRelativePathFromDirectory(req.SourceDirectory, info.FullName);

                files.Add(new FileMetadata
                {
                    FileName = info.Name,
                    SourcePath = info.FullName,
                    RelativePath = relative,
                    CreatedDate = info.CreationTimeUtc,
                    ModifiedDate = info.LastWriteTimeUtc
                });

                progress?.Report(++processed * 100 / total);
            }

            return files
                .OrderBy(f => f.EffectiveDate)
                .ToList();
        }

        public async Task OrganizeAsync(
            FileOrganizerRequest req,
            IProgress<int>? progress = null,
            CancellationToken ct = default)
        {
            int total = req.Files.Count, processed = 0;
            var log = new List<FileMetadata>();

            foreach (var file in req.Files)
            {
                ct.ThrowIfCancellationRequested();

                string yearFolder = Path.Combine(req.DestinationDirectory, file.Year.ToString());
                Directory.CreateDirectory(yearFolder);

                string dest = Path.Combine(yearFolder, file.FileName);
                file.OriginalDestinationPath = dest;

                // auto-rename on conflict
                int copyIndex = 1;
                while (File.Exists(dest))
                {
                    var name = Path.GetFileNameWithoutExtension(file.FileName);
                    var ext = Path.GetExtension(file.FileName);
                    var newName = $"{name} ({copyIndex++}){ext}";
                    dest = Path.Combine(yearFolder, newName);
                    file.WasRenamed = true;
                }

                file.DestinationPath = dest;
                File.Move(file.SourcePath, dest);

                log.Add(file);
                progress?.Report(++processed * 100 / total);
            }

            // write move-log.json
            var logJson = JsonSerializer.Serialize(log, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(Path.Combine(req.DestinationDirectory, "move-log.json"), logJson);
        }

        public async Task<List<FileMetadata>> LoadFromLogAsync(string logPath)
        {
            var json = await File.ReadAllTextAsync(logPath);
            return JsonSerializer.Deserialize<List<FileMetadata>>(json)!
                   ?? new List<FileMetadata>();
        }
    }

}
