namespace Frame.Contracts.V1;
public static class ApiRoutes
{
    // todo remove version
    public const string Version = "V1";
    public const string Root = "api";
    public const string Base = Root + "/" + Version;

    public static class Frames
    {
        public const string GetAll = Base + "/frames";
    }

    public static class Identity
    {
        public const string Signup = Base + "/identity/signup";
        
        public const string Login = Base + "/identity/login";

        public const string Refresh = Base + "/identity/refresh";

        public const string Test = Base + "/identity/test";
    }
}