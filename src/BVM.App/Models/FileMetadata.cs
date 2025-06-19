namespace BVM.App.Models
{
    public class FileMetadata
    {
        public string FileName { get; set; } = string.Empty;
        public string SourcePath { get; set; } = string.Empty;
        public string RelativePath { get; set; } = string.Empty;

        public DateTime? CreatedDate { get; set; }
        public DateTime? ModifiedDate { get; set; }

        public DateTime EffectiveDate =>
            CreatedDate ?? ModifiedDate ?? DateTime.MinValue;

        public int Year => EffectiveDate.Year;

        public string DestinationPath { get; set; } = string.Empty;
        public string DestinationRelativePath { get; set; } = string.Empty;

        // Keep track if we auto-renamed due to a conflict
        public bool WasRenamed { get; set; } = false;
        public string? OriginalDestinationPath { get; set; }
    }

    public class FileOrganizerRequest
    {
        public string SourceDirectory { get; set; } = string.Empty;
        public string DestinationDirectory { get; set; } = string.Empty;
        public List<FileMetadata> Files { get; set; } = new();
    }

}
