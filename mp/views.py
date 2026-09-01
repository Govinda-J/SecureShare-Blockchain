import functools
import traceback

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import timezone
from web3.exceptions import ContractLogicError, TransactionNotFound
from .models import Profile, File, Subscription, AccessRequest, AttributeKey, UserAttribute, AttributeRequest, ActivityLog
from .chain_client import (
    DataOwner,
    User as ChainUser,   
    register_user,
    login_user,
    sha256_hash,
    w3,
    UserAlreadyRegisteredError,
)
from .attributes import check_access_policy, get_user_attribute_dict
from .activity import log_activity
import os

from django.core.files.storage import default_storage
from django.conf import settings

# ---------------------------------------------------------------------
# BLOCKCHAIN ERROR HANDLING 
# ---------------------------------------------------------------------
def _clean_revert_reason(exc):
    """ Extract a readable error message from different Web3/provider exception formats. """
    message = getattr(exc, 'message', None)
    if message:
        return str(message).replace('execution reverted:', '').strip()

    if exc.args and isinstance(exc.args[0], dict):
        data = exc.args[0]
        text = data.get('message') or data.get('data') or ''
        if text:
            return str(text).replace('execution reverted:', '').strip()

    text = str(exc)
    if 'execution reverted' in text:
        return text.split('execution reverted:')[-1].strip(' "\'')
    return text or 'Unknown blockchain error'


def handle_chain_errors(redirect_to):
    """ Decorator used by views that interact with the blockchain.
        Blockchain errors are converted into Django messages instead of
        exposing raw exceptions or returning a server error page.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                return view_func(request, *args, **kwargs)
            except (ContractLogicError, TransactionNotFound, ValueError) as e:
                messages.warning(request, f'Blockchain error: {_clean_revert_reason(e)}')
            except Exception as e:
                traceback.print_exc()
                messages.warning(request, f'Unexpected error: {e}')
            return redirect(redirect_to(request, *args, **kwargs))
        return wrapper
    return decorator


# ---------------------------------------------------------------------
# HOME PAGE & AUTHENTICATION
# ---------------------------------------------------------------------
def home(request):
    return render(request, 'home.html')


def login(request):
    """ Authenticate the user through Django and then verify the user's 
        blockchain record using the private key stored in their Profile.
    """
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            try:
                profile = user.profile
            except Profile.DoesNotExist:
                messages.warning(request, 'No profile found for this account.')
                return render(request, 'login.html')

            private_key = profile.private_key
            user_data, private_key = login_user(username, password, private_key)
            if user_data is None:
                messages.warning(request, 'Could not verify your on-chain record. Please contact an admin.')
                return render(request, 'login.html')

            auth_login(request, user)
            messages.success(request, 'Login Successful')
            return redirect('dashboard')
        else:
            messages.warning(request, 'Invalid username or password.')

    return render(request, 'login.html')


def logout_view(request):
    auth_logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('home')


def register(request):
    """ Create a Django user and register the same user on the blockchain.
    
        Attributes are not collected during registration. They are assigned 
        later through the admin-controlled attribute system.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        private_key = request.POST.get('ethereum_private_key')
        name = request.POST.get('name')
        email = request.POST.get('email')

        if User.objects.filter(username=username).exists():
            messages.warning(request, 'Username already exists')
            return render(request, 'register.html')

        try:
            # Contract fields are passed as empty strings because
            # user attributes are managed separately by administrators.
            userID = register_user(username, password, name, email, '', '', private_key)
        except UserAlreadyRegisteredError:
            messages.warning(request, 'That username is already registered on-chain. Please login instead.')
            return render(request, 'register.html')
        except Exception as e:
            messages.warning(request, f'Could not register on-chain: {_clean_revert_reason(e)}')
            return render(request, 'register.html')

        user = User.objects.create_user(username=username, email=email, password=password)
        Profile.objects.create(user=user, name=name, private_key=private_key)

        auth_login(request, user)
        log_activity(user, 'register', f'Registered as "{username}"')

        messages.success(request, 'Registration successful!')
        return redirect('dashboard')

    return render(request, 'register.html')



# --- DASHBOARD HELPERS ---
def _owned_file_summaries(profile):
    files = File.objects.filter(owner=profile.user, is_deleted=False).order_by('-uploaded_at')
    return [{
        'file_name': f.file_name,
        'uploaded_at': f.uploaded_at,
        'pending': f.requests.filter(status='pending').count(),
        'approved': f.requests.filter(status='approved').count(),
        'rejected': f.requests.filter(status='rejected').count(),
    } for f in files]

# ============================= USER DASHBOARD =============================

@login_required
def dashboard(request):
    """ Main authenticated dashboard"""
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.warning(request, 'No profile found for this account.')
        return redirect('login')

    # Derive the wallet address from the private key stored in the profile.
    private_key = profile.private_key
    wallet_address = w3.eth.account.from_key(private_key).address

    # Show the user's most recent access requests.
    my_requests = AccessRequest.objects.filter(
        requester_username=profile.user.username
    ).select_related('file').order_by('-created_at')[:10]

    context = {
        'profile': profile,
        'wallet_address': wallet_address,
        'my_attributes': get_user_attribute_dict(profile),
        'my_requests': my_requests,
        'owned_files': _owned_file_summaries(profile),
        'pending_attr_requests': AttributeRequest.objects.filter(profile=profile, status='pending').count(),
    }
    return render(request, 'dashboard.html', context)

@login_required
def profile_view(request):
    """Display the authenticated user's profile and attribute requests."""
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.warning(request, 'No profile found for this account.')
        return redirect('login')

    private_key = profile.private_key
    context = {
        'profile': profile,
        'wallet_address': w3.eth.account.from_key(private_key).address,
        'my_attr_requests': AttributeRequest.objects.filter(profile=profile).order_by('-created_at'),
    }
    return render(request, 'profile.html', context)

@login_required
def activities_view(request):
    """Display recent activity belonging to the logged-in user."""
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.warning(request, 'No profile found for this account.')
        return redirect('login')

    context = {
        'activity': ActivityLog.objects.filter(user=profile.user)[:200],
    }
    return render(request, 'activities.html', context)

@login_required
def files_view(request):
    """ Display files owned by the user and files for which the user 
        has an approved or revoked access request.
    """
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.warning(request, 'No profile found for this account.')
        return redirect('login')

    accessible_files = AccessRequest.objects.filter(
        requester_username=profile.user.username,
        status__in=['approved', 'revoked'],
    ).select_related('file').order_by('-resolved_at')

    context = {
        'owned_files': _owned_file_summaries(profile),
        'accessible_files': accessible_files,
    }
    return render(request, 'files.html', context)

# --- USER ATTRIBUTE REQUESTS ---
@login_required
def request_attributes(request):
    """ Allow a user to request an attribute.
    
        The request itself does NOT assign the attribute. An administrator 
        must approve it before it becomes a trusted UserAttribute.
    """
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.warning(request, 'No profile found for this account.')
        return redirect('login')

    if request.method == 'POST':
        key = request.POST.get('key', '').strip()
        value = request.POST.get('value', '').strip()
        if key and value:
            if UserAttribute.objects.filter(profile=profile, key=key, value=value).exists():
                messages.info(request, f'You already have "{key}:{value}" assigned.')
                return redirect('request_attributes')
            if AttributeRequest.objects.filter(profile=profile, key=key, value=value, status='pending').exists():
                messages.info(request, f'You already have a pending request for "{key}:{value}".')
                return redirect('request_attributes')
            AttributeRequest.objects.create(profile=profile, key=key, value=value)
            AttributeKey.objects.get_or_create(name=key)
            log_activity(profile.user, 'request_attribute', f'Requested attribute "{key}:{value}"')
            messages.success(request, f'Requested "{key}:{value}" — an admin will review it.')
        else:
            messages.warning(request, 'Both key and value are required.')
        return redirect('request_attributes')

    context = {
        'attribute_keys': AttributeKey.objects.values_list('name', flat=True),
        'my_attr_requests': AttributeRequest.objects.filter(profile=profile).order_by('-created_at'),
    }
    return render(request, 'request_attributes.html', context)


# ============================= ADMIN DASHBOARD ======================

@staff_member_required
def admin_home(request):
    """ Administrator dashboard.
        Only Django staff users can access this view.
    """
    profiles = Profile.objects.select_related('user').prefetch_related('attributes').order_by('user__username')

    context = {
        'profiles': profiles,
        'total_users': profiles.count(),
        'total_files': File.objects.count(),
        'pending_count': AccessRequest.objects.filter(status='pending').count(),
        'approved_count': AccessRequest.objects.filter(status='approved').count(),
        'rejected_count': AccessRequest.objects.filter(status='rejected').count(),
        'attribute_requests': AttributeRequest.objects.filter(status='pending')
                                                .select_related('profile__user')
                                                .order_by('-created_at'),
        'activity': ActivityLog.objects.select_related('user')[:200],
    }
    return render(request, 'admin_home.html', context)

@staff_member_required
def resolve_attribute_request(request, req_id):
    """ Approve or reject a user's attribute request.
        Approval creates/updates the trusted UserAttribute record.
        Rejection simply marks the request as rejected.
    """
    attr_req = get_object_or_404(AttributeRequest, id=req_id)
    if attr_req.status != 'pending':
        messages.info(request, 'This request was already resolved.')
        return redirect('admin_home')
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'approve':
            UserAttribute.objects.update_or_create(
                profile=attr_req.profile, key=attr_req.key, defaults={'value': attr_req.value}
            )
            AttributeKey.objects.get_or_create(name=attr_req.key)
            attr_req.status = 'approved'
            attr_req.resolved_at = timezone.now()
            attr_req.save()
            log_activity(attr_req.profile.user, 'attribute_approved',
                         f'Your request for "{attr_req.key}:{attr_req.value}" was approved')
            messages.success(request, f'Approved "{attr_req.key}:{attr_req.value}" for {attr_req.profile.user.username}')
        elif action == 'reject':
            attr_req.status = 'rejected'
            attr_req.resolved_at = timezone.now()
            attr_req.save()
            log_activity(attr_req.profile.user, 'attribute_rejected',
                         f'Your request for "{attr_req.key}:{attr_req.value}" was rejected')
            messages.success(request, 'Attribute request rejected')
    return redirect('admin_home')

@staff_member_required
def manage_attributes(request, profile_id):
    """ Allow an administrator to directly add or remove 
        trusted attributes for a specific user.
    """

    profile = get_object_or_404(Profile, id=profile_id)

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'add':
            key = request.POST.get('key', '').strip()
            value = request.POST.get('value', '').strip()
            if key and value:
                UserAttribute.objects.update_or_create(
                    profile=profile, key=key, defaults={'value': value}
                )
                AttributeKey.objects.get_or_create(name=key)
                log_activity(profile.user, 'attribute_set', f'Attribute "{key}:{value}" set by admin')
                messages.success(request, f'Attribute "{key}" set for {profile.user.username}')
            else:
                messages.warning(request, 'Both key and value are required.')
        elif action == 'delete':
            attr_id = request.POST.get('attr_id')
            removed = UserAttribute.objects.filter(id=attr_id, profile=profile).first()
            if removed:
                log_activity(profile.user, 'attribute_removed', f'Attribute "{removed.key}:{removed.value}" removed by admin')
                removed.delete()
            messages.success(request, 'Attribute removed')
        return redirect('manage_attributes', profile_id=profile.id)

    context = {
        'profile': profile,
        'attribute_keys': AttributeKey.objects.values_list('name', flat=True),
    }
    return render(request, 'manage_attributes.html', context)



# ============================= ACCESS MANAGEMENT ======================
# ---------------------------------------------------------------------
# ACCESS REQUEST HELPERS
# ---------------------------------------------------------------------

def _build_details_with_policy_check(pending, policy):
    """Attach satisfies_policy to each pending request using admin-assigned attributes."""
    details = []
    for entry in pending:
        req_profile = Profile.objects.filter(user__username=entry['username']).first()
        attrs = get_user_attribute_dict(req_profile)
        satisfies = check_access_policy(policy, attrs)
        details.append({**entry, 'satisfies_policy': satisfies, 'attributes': attrs})
    return details


def _past_requests_for_file(filename):
    """
        Resolved (approved/rejected) requests for a file, 
        for displaying in Past Requests table.
    """
    file_obj = File.objects.filter(file_name=filename).first()
    if not file_obj:
        return []
    rows = AccessRequest.objects.filter(file=file_obj).exclude(status='pending').order_by('-resolved_at')
    result = []
    for r in rows:
        req_profile = Profile.objects.filter(user__username=r.requester_username).first()
        result.append({
            'username': r.requester_username,
            'attributes': get_user_attribute_dict(req_profile),
            'status': r.status,
            'resolved_at': r.resolved_at,
        })
    return result


def _filter_still_pending(filename, pending):
    """ 
        Filter blockchain requests using the local AccessRequest status.
    
        The blockchain keeps request IDs after they are processed, so the 
        local database is used to determine which requests are still pending.
    """
    if not pending or pending == "File Not Found":
        return pending
    file_obj = File.objects.filter(file_name=filename).first()
    if not file_obj:
        return pending
    still_pending_usernames = set(
        AccessRequest.objects.filter(file=file_obj, status='pending')
        .values_list('requester_username', flat=True)
    )
    return [p for p in pending if p['username'] in still_pending_usernames]


# ---------------------------------------------------------------------
# FILE ACCESS REQUEST
# ---------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('request'))
def requester(request):
    """ 
        Submit an access request for a file.
        The blockchain creates the request, while Django stores 
        a local record used to track its status.
    """
    profile = request.user.profile
    private_key = profile.private_key
    data_user = ChainUser(private_key)
    if request.method == 'POST':
        filename = request.POST.get('filename')

        file_obj = File.objects.filter(file_name=filename).order_by('-uploaded_at').first()

        if file_obj:
            # Owner has deleted the file.
            if file_obj.is_deleted:
                messages.warning(request, "File doesn't Exist")
                return redirect(reverse('files'))

            # Owner requesting access to their own file.
            if file_obj.owner == profile.user:
                messages.info(request, 'You already have access.')
                return redirect(reverse('files'))

            # Has this user already been through the grant flow for this file?
            existing = AccessRequest.objects.filter(
                file=file_obj, requester_username=profile.user.username
            ).order_by('-created_at').first()

            if existing:
                if existing.status == 'approved':
                    messages.info(request, 'You already have access.')
                    return redirect(reverse('files'))
                elif existing.status == 'revoked':
                    messages.warning(request, 'Your access has been revoked.')
                    return redirect(reverse('files'))
                elif existing.status == 'pending':
                    messages.info(request, 'Your request is already pending review.')
                    return redirect(reverse('dashboard'))

        # Create the access request on-chain.
        r, request_id = data_user.request_access(filename, profile.user.username)

        if r == 1:
            # Create the local record only after the blockchain request succeeds.
            file_obj, _ = File.objects.get_or_create(
                file_id=sha256_hash(filename.encode()).hex(),
                defaults={'file_name': filename},
            )
            AccessRequest.objects.create(
                file=file_obj,
                request_id=request_id,
                requester_username=profile.user.username,
                requester_address=w3.eth.account.from_key(private_key).address,
                status='pending',
            )
            log_activity(profile.user, 'request_access', f'Requested access to "{filename}"')
            if file_obj.owner:
                log_activity(file_obj.owner, 'request_access', f'"{profile.user.username}" requested access to "{filename}"')
            messages.success(request, f'Request for File:"{filename}" registered successfully!')
            return redirect(reverse('dashboard'))
        else:
            messages.warning(request, 'File not found')
            return render(request, 'request.html', {})
    return render(request, 'request.html', {})

# ---------------------------------------------------------------------
# ACCESS GRANTING
# ---------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('grant'))
def granter(request):
    """ Review and process access requests for files owned by the user."""
    profile = request.user.profile
    private_key = profile.private_key
    data_owner = DataOwner(private_key)
    owner_profile = profile
    username = owner_profile.user.username

    def _check(file, warn_if_empty=True):
        pending = _filter_still_pending(file, data_owner.get_pending_requests(file))
        past_requests = _past_requests_for_file(file)
        if pending == "File Not Found":
            if warn_if_empty:
                messages.warning(request, 'File Not Found')
            return None
        if not pending:
            if warn_if_empty:
                messages.warning(request, 'No Requests Yet')
            if past_requests:
                return render(request, 'grant.html', {
                    'details': [],
                    'filename': file, 'policy': data_owner.get_access_policy(file),
                    'past_requests': past_requests,
                })
            return None
        policy = data_owner.get_access_policy(file)
        details = _build_details_with_policy_check(pending, policy)
        return render(request, 'grant.html', {
            'details': details,
            'filename': file, 'policy': policy,
            'past_requests': past_requests,
        })

    if request.method == 'POST':
        file = request.POST.get('filename')
        action = request.POST.get('action')

        if action == 'check':
            result = _check(file)
            if result is not None:
                return result

        elif action == 'grant':
            # target_username set => per-row "Process" button (one request);
            # unset => "Process All Requests" button (every pending request).
            target_username = request.POST.get('target_username', '').strip()

            pending_raw = data_owner.get_pending_requests(file)
            if pending_raw == "File Not Found":
                messages.warning(request, 'File not found, or you are not its owner.')
                return render(request, 'grant.html', {})
            
            pending = _filter_still_pending(file, pending_raw)
            policy = data_owner.get_access_policy(file)
            details = _build_details_with_policy_check(pending, policy)
            if target_username:
                details = [d for d in details if d['username'] == target_username]
                if not details:
                    messages.warning(request, f'No pending request found for "{target_username}" — it may already be processed.')
                    return _check(file, warn_if_empty=False) or render(request, 'grant.html', {})

            # DataOwner handles the blockchain-side grant/rejection operation.
            granted = data_owner.grant_access(file, details, username)
            granted_usernames = {u for u, _ in granted}

            file_obj, _ = File.objects.get_or_create(
                file_id=sha256_hash(file.encode()).hex(),
                defaults={'file_name': file},
            )

            # Synchronize local request status with the blockchain result.
            for entry in details:
                req_row = AccessRequest.objects.filter(
                    file=file_obj, requester_username=entry['username'], status='pending'
                ).first()
                was_granted = entry['username'] in granted_usernames
                if req_row:
                    req_row.status = 'approved' if was_granted else 'rejected'
                    req_row.resolved_at = timezone.now()
                    req_row.save()

                # Log from both the owner's and the requester's perspective.
                req_profile = Profile.objects.filter(user__username=entry['username']).first()
                if was_granted:
                    log_activity(owner_profile.user, 'grant', f'Granted "{entry["username"]}" access to "{file}"')
                    if req_profile:
                        log_activity(req_profile.user, 'grant', f'Your request for "{file}" was approved')
                else:
                    log_activity(owner_profile.user, 'reject', f'Rejected "{entry["username"]}"\'s request for "{file}"')
                    if req_profile:
                        log_activity(req_profile.user, 'reject', f'Your request for "{file}" was rejected')

            # Store subscription keys locally for users who received access.
            for uname, subs_key_hex in granted:
                sub, _ = Subscription.objects.get_or_create(file=file_obj, user_id=uname)
                if subs_key_hex not in sub.user_keys:
                    sub.user_keys = sub.user_keys + [subs_key_hex]
                    sub.user_names = sub.user_names + [uname]
                    sub.save()

            # Recalculate the file's coefficients using all active keys.
            all_keys = []
            for sub in Subscription.objects.filter(file=file_obj):
                all_keys.extend(sub.user_keys)
            if all_keys:
                data_owner.recompute_and_publish_coefficients(file, all_keys)

            messages.success(request, 'Requests processed!')
            return _check(file, warn_if_empty=False) or render(request, 'grant.html', {})

    elif request.GET.get('filename'):
       # Used when opening the grant page directly from the files page.
        result = _check(request.GET['filename'])
        if result is not None:
            return result

    return render(request, 'grant.html', {})

# ---------------------------------------------------------------------
# ACCESS REVOCATION
# ---------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('revoke'))
def revoker(request):
    """ 
    Show users with active access to a file and revoke selected users.
    """
    profile = request.user.profile
    private_key = profile.private_key
    data_owner = DataOwner(private_key)
    owner_profile = profile

    def _get_users(filename):
        file_obj = File.objects.filter(file_name=filename).first()
        if not file_obj:
            messages.warning(request, 'File Not Found')
            return None
        subs = Subscription.objects.filter(file=file_obj)
        users = [name for sub in subs for name in sub.user_names]
        if not users:
            messages.warning(request, 'No Users Found')
            return None
        return render(request, 'revoke.html', {'users': users, 'filename': filename})

    if request.method == 'POST':
        filename = request.POST.get('filename')
        action = request.POST.get('action')
        file_obj = File.objects.filter(file_name=filename).first()

        if action == 'Get Users':
            result = _get_users(filename)
            if result is not None:
                return result

        elif action == 'Revoke':
            selected_users = request.POST.getlist('users')

            revoked_request_ids = list(
                AccessRequest.objects.filter(
                    file=file_obj, requester_username__in=selected_users, status='approved'
                ).values_list('request_id', flat=True)
            )
            if not revoked_request_ids:
                messages.info(request, 'Selected users already have no active access.')
                return redirect(reverse('files'))

            revoked_request_ids = list(
                AccessRequest.objects.filter(
                    file=file_obj, requester_username__in=selected_users, status='approved'
                ).values_list('request_id', flat=True)
            )    

            # Remove selected users' keys and preserve keys of other users.
            subs = Subscription.objects.filter(file=file_obj)
            remaining_keys = []
            for sub in subs:
                if sub.user_id in selected_users:
                    sub.delete()
                else:
                    remaining_keys.extend(sub.user_keys)


            data_owner.revoke_access(filename, remaining_keys, revoked_request_ids)

            # Update local request status and activity logs.
            for uname in selected_users:
                req_row = AccessRequest.objects.filter(
                    file=file_obj, requester_username=uname, status='approved'
                ).first()
                if req_row:
                    req_row.status = 'revoked'
                    req_row.resolved_at = timezone.now()
                    req_row.save()

                log_activity(owner_profile.user, 'revoke', f'Revoked "{uname}"\'s access to "{filename}"')
                revoked_profile = Profile.objects.filter(user__username=uname).first()
                if revoked_profile:
                    log_activity(revoked_profile.user, 'revoke', f'Your access to "{filename}" was revoked')

            messages.success(request, 'Access Revoked')
            return redirect(reverse('files'))

    elif request.GET.get('filename'):
        # Used when opening the revoke page directly from the files page.
        result = _get_users(request.GET['filename'])
        if result is not None:
            return result

    return render(request, 'revoke.html', {})

# ---------------------------------------------------------------------
# ACCESS REQUEST MANAGEMENT
# ---------------------------------------------------------------------
@login_required
def dismiss_access_request(request, req_id):
    """
        Remove an access request from the current user's local request list.
    """
    if request.method == 'POST':
        req_row = AccessRequest.objects.filter(id=req_id, requester_username=request.user.username).first()
        if req_row:
            req_row.delete()
            messages.success(request, 'Removed from your list.')
        else:
            messages.warning(request, 'Could not find that entry.')
    next_url = request.POST.get('next') or reverse('files')
    return redirect(next_url)



# ========================== FILE OPERATIONS ========================

# ---------------------------------------------------------------------
# FILE UPLOAD
# ---------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('upload'))
def uploader(request):
    """ Upload a file as the current user
        File operation handled by DataOwner
    """
    profile = request.user.profile
    private_key = profile.private_key
    data_owner = DataOwner(private_key)
    owner_profile = profile
    if request.method == 'POST':
        if 'file' in request.FILES:
            uploaded_file = request.FILES['file']
            file_name = uploaded_file.name

            # The uploaded file is temporarily written to disk because
            # # the blockchain client expects a local file path.
            import tempfile

            with tempfile.TemporaryDirectory() as tmp_dir:
                file_path = os.path.join(tmp_dir, file_name)
                with open(file_path, 'wb+') as destination:
                    for chunk in uploaded_file.chunks():
                        destination.write(chunk)

                # access_policy is now fully owner-defined key:value pairs,
                access_policy = request.POST.get('access_policy', '').strip()
                if not access_policy:
                    messages.error(request, 'At least one access policy attribute is required.')
                    return redirect(reverse('upload'))

                existing_file = File.objects.filter(file_name=file_name, is_deleted=False).first()
                if existing_file and existing_file.owner != owner_profile.user:
                    messages.error(request, f'A file named "{file_name}" already exists under a different owner. Please rename your file.')
                    return redirect(reverse('upload'))
                
                # Upload the file and store its access policy on-chain.
                r = data_owner.upload_file(file_path, access_policy)
                file_tag_hex = sha256_hash(file_name.encode()).hex()

            # Create/update the local metadata record.
            file_obj, created = File.objects.get_or_create(
                file_id=file_tag_hex,
                defaults={'file_name': file_name, 'owner': owner_profile.user},
            )
            if not created and (file_obj.owner is None or file_obj.is_deleted):
                file_obj.owner = owner_profile.user
                file_obj.file_name = file_name
                file_obj.is_deleted = False
                file_obj.deleted_at = None
                file_obj.save()

            if r[0] == 1:
                messages.success(request, f'File "{file_name}" already exists — metadata updated on-chain')
                log_activity(owner_profile.user, 'upload', f'Updated metadata for "{file_name}"')
            elif r[0] == 2:
                messages.warning(request, f'A different file already exists under this name: "{r[1]}"')
            elif r[0] == 3:
                messages.success(request, f'File "{file_name}" uploaded and metadata stored on-chain')
                log_activity(owner_profile.user, 'upload', f'Uploaded "{file_name}"')

            return redirect(reverse('files'))
        else:
            messages.error(request, 'No file selected!')
            return redirect(reverse('upload'))

    return render(request, 'upload.html', {
        'attribute_keys': AttributeKey.objects.values_list('name', flat=True),
    })

# ---------------------------------------------------------------------
# OWNER FILE DOWNLOAD
# ---------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('files'))
def owner_downloader(request):
    """ Download a file directly as its owner. """
    profile = request.user.profile
    data_owner = DataOwner(profile.private_key)

    if request.method == 'POST':
        filename = request.POST.get('filename')
        file_obj = File.objects.filter(file_name=filename, owner=profile.user, is_deleted=False).first()
        if not file_obj:
            messages.warning(request, 'File not found or you are not its owner.')
            return redirect(reverse('files'))

        r = data_owner.owner_download_file(filename)
        if r == 1:
            messages.success(request, f'Downloaded File:"{filename}" successfully!')
            log_activity(profile.user, 'download', f'Downloaded "{filename}" (as owner)')
        elif r == -3:
            messages.warning(request, 'You are not an owner of this file on-chain.')
        elif r == -1:
            messages.warning(request, 'File not found on-chain.')

    return redirect(reverse('files'))

# -----------------------------------------------------------------------
# USER FILE DOWNLOAD
# -----------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('download'))
def downloader(request):
    """ 
        Download a file as a user who has requested access.
        ChainUser performs the blockchain-side permission and decryption logic.
    """
    profile = request.user.profile
    private_key = profile.private_key
    data_user = ChainUser(private_key)
    if request.method == 'POST':
        filename = request.POST.get('filename')
        r = data_user.download_and_decrypt_file(filename, profile.user.username)
        if r == 0:
            messages.success(request, f'Request for File:"{filename}" under process')
        elif r == 1:
            messages.success(request, f'Downloaded File:"{filename}" successfully!')
            log_activity(profile.user, 'download', f'Downloaded "{filename}"')
        elif r == 2:
            messages.warning(request, 'Permission Denied')
        elif r == -2:
            messages.warning(request, 'You have not requested access. Permission Denied')
        elif r == -1:
            messages.warning(request, 'File not found')

    return render(request, 'download.html', {})

# ---------------------------------------------------------------------
# FILE DELETION
# ---------------------------------------------------------------------
@login_required
@handle_chain_errors(lambda request: reverse('files'))
def delete_file(request):
    """ 
        Delete a file owned by the current user.
        Access is revoked before the local file metadata is marked deleted.
    """
    profile = request.user.profile
    private_key = profile.private_key
    data_owner = DataOwner(private_key)

    if request.method == 'POST':
        filename = request.POST.get('filename')
        # Ensure the current user owns the file before deleting it.
        file_obj = File.objects.filter(file_name=filename, owner=profile.user, is_deleted=False).first()
        if not file_obj:
            messages.warning(request, 'File not found or you are not its owner.')
            return redirect(reverse('files'))

        revoked_request_ids = list(
            AccessRequest.objects.filter(file=file_obj, status='approved').values_list('request_id', flat=True)
        )

        data_owner.delete_file(filename, revoked_request_ids)

        # Mark all active requests as revoked locally.
        for req_row in AccessRequest.objects.filter(file=file_obj, status='approved'):
            req_row.status = 'revoked'
            req_row.resolved_at = timezone.now()
            req_row.save()
            revoked_profile = Profile.objects.filter(user__username=req_row.requester_username).first()
            if revoked_profile:
                log_activity(revoked_profile.user, 'revoke', f'"{filename}" was deleted by its owner — your access has ended')
        Subscription.objects.filter(file=file_obj).delete()

        # Soft-delete the local file record rather than removing it permanently.
        file_obj.is_deleted = True
        file_obj.deleted_at = timezone.now()
        file_obj.save()

        log_activity(profile.user, 'file_deleted', f'Deleted "{filename}"')
        messages.success(request, f'"{filename}" has been deleted.')
        return redirect(reverse('files'))

    return redirect(reverse('files'))
