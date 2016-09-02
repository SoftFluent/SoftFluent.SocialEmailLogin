<%@ Page Title="Home Page" Language="C#" AutoEventWireup="true" %>

<%@ Import Namespace="SoftFluent.SocialEmailLogin.Configuration" %>
<%@ Import Namespace="SoftFluent.SocialEmailLogin" %>

<!DOCTYPE html>
<html lang="en">
<head id="Head1" runat="server">
    <title>SoftFluent SocialLogin</title>
    <link href="~/Styles/Site.css" rel="stylesheet" type="text/css" />
</head>
<body>
    <form id="Form1" runat="server">
        <div class="page">
            <div class="header">
                <div class="title">
                    <h1>SoftFluent SocialLogin</h1>
                </div>
                <div class="loginDisplay">
                    <asp:LoginView ID="HeadLoginView" runat="server" EnableViewState="false">
                        <AnonymousTemplate>
                            You are not logged in
                        </AnonymousTemplate>
                        <LoggedInTemplate>
                            Welcome <span class="bold">
                                <asp:LoginName ID="HeadLoginName" runat="server" />
                            </span>! [
                            <asp:LoginStatus ID="HeadLoginStatus" runat="server" LogoutAction="Redirect" LogoutText="Log Out" LogoutPageUrl="~/" />
                            ]
                        </LoggedInTemplate>
                    </asp:LoginView>
                </div>
            </div>
            <div class="main">
                <h2>SoftFluent SocialLogin Demo!</h2>

                <% if (User.Identity.IsAuthenticated)
                   { %>

                <p class="on">
                    You are logged in!
                </p>

                <% } else { %>

                <div class="socialLogin">
                    <asp:LinkButton ID="imgLoginFacebook" runat="server" CommandName="Facebook" CssClass="f" OnClick="imgLogin_Click" Text="Facebook" />
                    <asp:LinkButton ID="imgLoginGoogle" runat="server" CommandName="Google" CssClass="g" OnClick="imgLogin_Click" Text="Google" />
                    <asp:LinkButton ID="imgLoginLive" runat="server" CommandName="Microsoft" CssClass="m" OnClick="imgLogin_Click" Text="Microsoft" />
                    <asp:LinkButton ID="imgLoginYahoo" runat="server" CommandName="Yahoo" CssClass="y" OnClick="imgLogin_Click" Text="Yahoo" />
                    <asp:LinkButton ID="imgLoginTwitter" runat="server" CommandName="Twitter" CssClass="t" OnClick="imgLogin_Click" Text="Twitter" />
                    <asp:LinkButton ID="ImgLoginLinkedIn" runat="server" CommandName="LinkedIn" CssClass="l" OnClick="imgLogin_Click" Text="LinkedIn" />
                    <asp:LinkButton ID="ImgLoginYammer" runat="server" CommandName="Yammer" class="yam" OnClick="imgLogin_Click" Text="Yammer" />
                    <asp:LinkButton ID="ImgLoginAzureAD" runat="server" CommandName="AzureAD" class="a" OnClick="imgLogin_Click" Text="AzureAD" />
                </div>

                <% } %>
            </div>
            <p class="warning">Warning: this is not possible to retrieve the email address for a twitter account. Instead, we create an email based on the twitter screen_name.</p>
        </div>
    </form>
</body>
</html>

<script runat="server">
    protected void imgLogin_Click(object sender, EventArgs e)
    {
        LinkButton button = (LinkButton)sender;
        AuthServiceProvider provider = SocialEmailLoginSection.Current.Authentication.GetServiceProvider(button.CommandName);
        if (provider != null)
        {
            provider.Login(AuthLoginOptions.None);
        }
    }
</script>
