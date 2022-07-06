using Frame.Infrastructure.Providers.Base;

namespace Frame.Infrastructure.Providers;
public class DateTimeNowProvider : IDateTimeProvider
{
    public DateTime GetDateTime() => DateTime.Now;
}
