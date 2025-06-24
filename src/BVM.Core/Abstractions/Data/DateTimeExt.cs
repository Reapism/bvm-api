namespace BVM.Core.Abstractions.Data
{
    public static class DateTimeExt
    {
        public static DateTimeOffset ToESTTime(this DateTimeOffset dateTime)
        {

            var estTimeZoneInfo = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
            var estDateTimeOffset = TimeZoneInfo.ConvertTime(dateTime, estTimeZoneInfo);

            return estDateTimeOffset;

        }

        public static DateTime ToESTTime(this DateTime dateTime)
        {

            var estTimeZoneInfo = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
            var estDateTimeOffset = TimeZoneInfo.ConvertTime(dateTime, estTimeZoneInfo);

            return estDateTimeOffset;
        }
    }
}
