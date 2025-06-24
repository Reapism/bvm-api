namespace BVM.Core.Abstractions.Data
{
    public class EasternDateTimeProvider : IDateTimeProvider
    {
        public DateTime Now
        {
            get
            {
                return DateTime.Now.ToESTTime();
            }
        }
    }
}
