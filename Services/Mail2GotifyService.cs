using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SmtpServer;
using SmtpServer.ComponentModel;
using SmtpServer.Net;
using SmtpServer.Tracing;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Mail2Gotify.Services
{
    public class Mail2GotifyService(CacheItemProcessingService cacheItemProcessingService, GotifyMessageStore gotifyMessageStore, GotifyUserAuthenticator gotifyUserAuthenticator, IConfiguration configuration, ILogger<Mail2GotifyService> logger) : IHostedService
    {
        private readonly CacheItemProcessingService _cacheItemProcessingService = cacheItemProcessingService;
        private readonly GotifyMessageStore _gotifyMessageStore = gotifyMessageStore;
        private readonly GotifyUserAuthenticator _gotifyUserAuthenticator = gotifyUserAuthenticator;
        private readonly IConfiguration _configuration = configuration;
        private readonly ILogger<Mail2GotifyService> _logger = logger;

        private SmtpServer.SmtpServer _smtpServer;

        static CancellationToken _cancellationToken;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await _cacheItemProcessingService.ProcessCacheItems();

            string certLocation = _configuration["Services:Mail2Gotify:CertLocation"];

            FileInfo certFileInfo = null;
            if (!string.IsNullOrWhiteSpace(certLocation))
                certFileInfo = new(certLocation);

            if (certFileInfo != null && !certFileInfo.Exists)
                throw new ArgumentException("The cert file configuration and set but the file doesn't exist!");

            string keyLocation = _configuration["Services:Mail2Gotify:KeyLocation"];

            FileInfo keyFileInfo = null;
            if (!string.IsNullOrWhiteSpace(keyLocation))
                keyFileInfo = new(keyLocation);

            if (keyFileInfo != null && !keyFileInfo.Exists)
                throw new ArgumentException("The key file configuration and set but the file doesn't exist!");
                
            string certPassword = _configuration["Services:Mail2Gotify:CertPassword"];
            
            string certType = _configuration["Services:Mail2Gotify:CertType"] ?? "PEM";
            if (certType != "PEM" && certType != "PKCS7")
                throw new ArgumentException("The configured cert type must be either PEM or PKCS7!");
            
            X509Certificate x509Certificate = null;
            if (certFileInfo == null)
                x509Certificate = CreateX509Certificate2();   
            if (certType == "PEM" && !string.IsNullOrWhiteSpace(certPassword))            
                x509Certificate = X509Certificate2.CreateFromEncryptedPemFile(certFileInfo.FullName, certPassword, keyFileInfo?.FullName);            
            else if (certType == "PEM")            
                x509Certificate = X509Certificate2.CreateFromPemFile(certFileInfo.FullName, keyFileInfo?.FullName);
            else if (certType == "PKCS7")
                x509Certificate = X509Certificate.CreateFromCertFile(certFileInfo.FullName);   

            ISmtpServerOptions options = new SmtpServerOptionsBuilder()
              .ServerName(_configuration["Services:Mail2Gotify:HostAddress"])
              .Endpoint(builder =>
                builder                
                .Port(_configuration.GetValue<int>("Services:Mail2Gotify:HostPort"))
                .IsSecure(_configuration.GetValue<bool>("Services:Mail2Gotify:Secure"))
                .AllowUnsecureAuthentication(true)
                .AuthenticationRequired()
                .SupportedSslProtocols(System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13)
                .Certificate(x509Certificate))
                .Build();

            

            ServiceProvider serviceProvider = new();
            serviceProvider.Add(_gotifyMessageStore);
            serviceProvider.Add(_gotifyUserAuthenticator);

            _logger.Log(LogLevel.Information, $"Mail2Gotify server starting!");

            _smtpServer = new SmtpServer.SmtpServer(options, serviceProvider);

            _cancellationToken = cancellationToken;
            _smtpServer.SessionCreated += OnSessionCreated;

            await _smtpServer.StartAsync(cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.Log(LogLevel.Information, $"Mail2Gotify server stopping!");

            #pragma warning disable CA2016 // We don't want to cancel waiting, server will receive SIGKILL if taking too long.
            Task.WaitAll(_smtpServer.ShutdownTask);
            #pragma warning restore CA2016 // We don't want to cancel waiting, server will receive SIGKILL if taking too long.

            return Task.CompletedTask;
        }

        public X509Certificate2 CreateX509Certificate2()
        {
            RSA rsa = RSA.Create();
            CertificateRequest certificateRequest = new($"cn={_configuration["SelfSignedCertificate:Name"]}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

            return new X509Certificate2(certificate.Export(X509ContentType.Pfx, _configuration["SelfSignedCertificate:Password"]), _configuration["SelfSignedCertificate:Password"]);
        }

                static void OnSessionFaulted(object sender, SessionFaultedEventArgs e)
        {
            Console.WriteLine("SessionFaulted: {0}", e.Exception);
        }

        static void OnSessionCancelled(object sender, SessionEventArgs e)
        {
            Console.WriteLine("SessionCancelled");
        }

        static void OnSessionCreated(object sender, SessionEventArgs e)
        {
            e.Context.Properties.Add("SessionID", Guid.NewGuid());

            e.Context.CommandExecuting += OnCommandExecuting;
            e.Context.CommandExecuted += OnCommandExecuted;
            e.Context.ResponseException += OnResponseException;
        }

        private static void OnResponseException(object sender, SmtpResponseExceptionEventArgs e)
        {
            Console.WriteLine("Response Exception");
            if (e.Exception.Properties.ContainsKey("SmtpSession:Buffer"))
            {
                var buffer = e.Exception.Properties["SmtpSession:Buffer"] as byte[];
                Console.WriteLine("Unrecognized Command: {0}", Encoding.UTF8.GetString(buffer));
            }
        }

        static void OnCommandExecuting(object sender, SmtpCommandEventArgs e)
        {
            Console.WriteLine("Command Executing (SessionID={0})", e.Context.Properties["SessionID"]);
            new TracingSmtpCommandVisitor(Console.Out).Visit(e.Command);
        }

        static void OnCommandExecuted(object sender, SmtpCommandEventArgs e)
        {
            Console.WriteLine("Command Executed (SessionID={0})", e.Context.Properties["SessionID"]);
            new TracingSmtpCommandVisitor(Console.Out).Visit(e.Command);
        }

        static void OnSessionCompleted(object sender, SessionEventArgs e)
        {
            Console.WriteLine("SessionCompleted: {0}", e.Context.Properties[EndpointListener.RemoteEndPointKey]);

            e.Context.CommandExecuting -= OnCommandExecuting;
            e.Context.CommandExecuted -= OnCommandExecuted;
            e.Context.ResponseException -= OnResponseException;

            CancellationTokenSource _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(_cancellationToken);
            _cancellationTokenSource.Cancel();
        }
    }
}
