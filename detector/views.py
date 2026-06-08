import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import ScanResult
from .analyzer import analyze_url
from .email_scanner import get_flow, scan_emails
import json


@login_required
def index(request):
    result = None

    if request.method == 'POST':
        url = request.POST.get('url')
        analysis = analyze_url(url)

        ScanResult.objects.create(
            user=request.user,
            url=url,
            is_phishing=analysis['is_phishing'],
            risk_score=analysis['risk_score'],
            reasons='\n'.join(analysis['reasons'])
        )

        result = {
            'url': url,
            'is_phishing': analysis['is_phishing'],
            'risk_score': analysis['risk_score'],
            'reasons': analysis['reasons']
        }

    return render(request, 'detector/index.html', {'result': result})


@login_required
def history(request):
    scans = ScanResult.objects.filter(user=request.user).order_by('-scanned_at')
    return render(request, 'detector/history.html', {'scans': scans})


@login_required
def dashboard(request):
    scans = ScanResult.objects.filter(user=request.user)
    total = scans.count()
    phishing_count = scans.filter(is_phishing=True).count()
    safe_count = scans.filter(is_phishing=False).count()
    recent_scans = scans.order_by('-scanned_at')[:5]

    scans_by_risk = {
        'low': scans.filter(risk_score__lte=25).count(),
        'medium': scans.filter(risk_score__gt=25, risk_score__lte=50).count(),
        'high': scans.filter(risk_score__gt=50, risk_score__lte=75).count(),
        'critical': scans.filter(risk_score__gt=75).count(),
    }

    context = {
        'total': total,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'recent_scans': recent_scans,
        'scans_by_risk': scans_by_risk,
    }
    return render(request, 'detector/dashboard.html', context)


@login_required
def bulk_scan(request):
    results = []

    if request.method == 'POST':
        urls_text = request.POST.get('urls')
        urls = [u.strip() for u in urls_text.splitlines() if u.strip()]

        for url in urls:
            analysis = analyze_url(url)
            ScanResult.objects.create(
                user=request.user,
                url=url,
                is_phishing=analysis['is_phishing'],
                risk_score=analysis['risk_score'],
                reasons='\n'.join(analysis['reasons'])
            )
            results.append({
                'url': url,
                'is_phishing': analysis['is_phishing'],
                'risk_score': analysis['risk_score'],
                'reasons': analysis['reasons']
            })

    return render(request, 'detector/bulk_scan.html', {'results': results})


@login_required
def email_scan(request):
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent',
    )
    request.session['oauth_state'] = state
    request.session.modified = True
    return redirect(auth_url)


@login_required
def email_scan_callback(request):
    try:
        state = request.session.get('oauth_state')
        flow = get_flow()
        flow.fetch_token(
            authorization_response=request.build_absolute_uri().replace('http://', 'https://'),
            state=state,
        )
        credentials = flow.credentials
        token_json = credentials.to_json()
        emails = scan_emails(token_json)

        print(f"Total emails fetched: {len(emails)}")
        for e in emails[:3]:
            print(f"Subject: {e['subject']}")
            print(f"URLs found: {e['urls']}")

        email_results = []
        for email in emails:
            scanned_urls = []
            has_phishing = False
            for url in email['urls']:
                try:
                    analysis = analyze_url(url)
                    ScanResult.objects.create(
                        user=request.user,
                        url=url,
                        is_phishing=analysis['is_phishing'],
                        risk_score=analysis['risk_score'],
                        reasons='\n'.join(analysis['reasons'])
                    )
                    scanned_urls.append({
                        'url': url,
                        'is_phishing': analysis['is_phishing'],
                        'risk_score': analysis['risk_score'],
                    })
                    if analysis['is_phishing']:
                        has_phishing = True
                except:
                    pass
            email_results.append({
                'subject': email['subject'],
                'sender': email['sender'],
                'scanned_urls': scanned_urls,
                'has_phishing': has_phishing,
                'url_count': len(scanned_urls)
            })
        return render(request, 'detector/email_scan.html', {
            'email_results': email_results
        })
    except Exception as e:
        print(f"Error: {e}")
        return render(request, 'detector/email_scan.html', {
            'email_results': [],
            'error': str(e)
        })