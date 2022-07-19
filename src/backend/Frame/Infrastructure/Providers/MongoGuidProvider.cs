using Frame.Infrastructure.Providers.Base;

namespace Frame.Infrastructure.Providers;
public class MongoGuidProvider : IGuidProvider
{
    public string GetGuid() => MongoDB.Bson.ObjectId.GenerateNewId().ToString();
}
