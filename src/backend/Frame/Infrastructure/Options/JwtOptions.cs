namespace Frame.Infrastructure.Options;
public class JwtOptions
{
    public string Secret { get; set; } = null!;
    public TimeSpan TokenLifeTime { get; set; } 
}
