from django import forms
from django.apps import apps
from django.db.models import F, Q, Max
from django.shortcuts import render
from django.conf import settings
from django.contrib.postgres.search import TrigramSimilarity
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models.signals import pre_save, post_save
from django.urls import reverse, reverse_lazy
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.contrib.messages import get_messages
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.shortcuts import render_to_response
from django.utils.decorators import method_decorator
from django.utils.encoding import smart_str
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View, TemplateView, DetailView
from django.views.generic.base import ContextMixin
from django.views.generic.edit import FormView, CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView
from django.utils import timezone
from datetime import date, datetime, timedelta
from dateutil.relativedelta import relativedelta
import logging
import uuid
# Avoid shadowing the login() and logout() views below.
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login  as auth_login,
    logout  as auth_logout, update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse, HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.template.response import TemplateResponse
from django.utils.encoding import force_text
from django.utils.http import is_safe_url, urlsafe_base64_decode
from django.utils.six.moves.urllib.parse import urlparse, urlunparse
from django.utils.translation import ugettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.db import transaction
from decimal import Decimal
from dateutil import parser
import traceback
import operator

from django.utils.encoding import smart_str
from .forms import *
from common.forms import ChangePasswordForm
from common.templatetags.custom_template import get_disp_value, get_datetime_disp_value, error_code_to_string, get_date_disp_value
from common.standard_functions import transform_phone, send_email_message, find_file_extension, find_filename_without_extension, remove_spl_char, convert_time_str_to_time_arr, get_current_year, create_pdf_document, merge_pdf_files, validate_mobile_countryCode
from common.utility_functions import generate_username, create_notification, get_call_ticket_list_for_customer, can_access_groupname, can_access_itemname, can_access_fieldname, get_open_ticket_list, get_unread_notifications, get_engineer_report, get_auto_assign_engineer_id, get_admin_users_with_edit_call_access_for_a_call, get_vendor_data, get_open_ticket_dependency_report, if_next_engineer_available_job, get_auto_assign_engineer_id_using_callticket_id, process_alert_emails_for_callobj, get_engineers_latest_available_time, transform_email_content, get_table_formatted_call_details, reassign_new_engineer_after_rejection, get_status_tracking_report, get_asset_data_list, get_first_last_day_of_month
from common.views import class_view_decorator
from common.models import *
from common.lenovo import send_call_ticket_status_change

import csv
import json
import pyotp
import pytz
import requests
import threading
import uuid
import csv
import time


logger = logging.getLogger(__name__)

class AdditionalContextMixin(ContextMixin):

    def get_context_data(self, **kwargs):
        context = super(AdditionalContextMixin,self).get_context_data(**kwargs)
        if self.request.user.is_authenticated:
            unread_notifications = get_unread_notifications(self.request.user)
            if unread_notifications:
                context['unread_notification_count'] = unread_notifications.count()
            else:
                context['unread_notification_count'] = 0
        return context


@class_view_decorator(login_required)
class AdminTemplateView(SuccessMessageMixin, TemplateView, AdditionalContextMixin):
    redirecturl = 'administrations:admin_home'

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)


@class_view_decorator(login_required)
class AdminFormView(SuccessMessageMixin, FormView, AdditionalContextMixin):
    redirecturl = 'administrations:admin_home'

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)


@class_view_decorator(login_required)
class AdminListView(SuccessMessageMixin, ListView, AdditionalContextMixin):
    redirecturl = 'administrations:admin_home'   

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)


@class_view_decorator(login_required)
class AdminUpdateView(SuccessMessageMixin, UpdateView, AdditionalContextMixin):
    redirecturl = 'administrations:admin_home'

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)


@class_view_decorator(login_required)
class AdminCreateView(SuccessMessageMixin, CreateView, AdditionalContextMixin):
    redirecturl = 'administrations:admin_home'

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)


@class_view_decorator(login_required)
class AdminDeleteView(SuccessMessageMixin, DeleteView, AdditionalContextMixin):
    redirecturl = 'admin_home'

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)


def call_ticket_pre_save_signal_receiver(sender, **kwargs):
    callobj = kwargs['instance']
    if callobj.pk:
        callobj = kwargs['instance']
        oldobj = CallTicket.objects.get(pk = callobj.pk)
        callobj.old_status = oldobj.status
        callobj.old_reason_code = oldobj.reason_code

pre_save.connect(call_ticket_pre_save_signal_receiver, sender = CallTicket)


def call_ticket_post_save_signal_receiver(sender, **kwargs):
    callobj = kwargs['instance']
    auto_emails = None
    if kwargs.get('created'):
        auto_emails = AutoEmail.objects.filter(tenant = callobj.tenant, vendor = callobj.vendor, trigger = AutoEmail.TRIGGER_CALL_CREATE)
        ProcessAlertForCallTicketsThread(callobj).start()
    else:
        if callobj.status != callobj.old_status:
            auto_emails = AutoEmail.objects.filter(tenant = callobj.tenant, vendor = callobj.vendor, trigger = AutoEmail.TRIGGER_CALL_STATUS_CHANGE, call_status = callobj.status)
        if not auto_emails or (not auto_emails.exists() and callobj.reason_code != callobj.old_reason_code):
            auto_emails = AutoEmail.objects.filter(tenant = callobj.tenant, vendor = callobj.vendor, trigger = AutoEmail.TRIGGER_CALL_REASON_CODE_CHANGE, reason_code = callobj.reason_code)
        if callobj.vendor_id == 1:
            if callobj.status != callobj.old_status or callobj.reason_code != callobj.old_reason_code:
                call_status_obj = None
                call_reason_code_obj = None
                if callobj.status:
                    call_status_obj = CallStatus.objects.get(pk = callobj.status.id)
                if callobj.reason_code:
                    call_reason_code_obj = ReasonCode.objects.get(pk = callobj.reason_code.id)
                if call_status_obj and call_reason_code_obj and call_status_obj.vendor_key and call_reason_code_obj.vendor_key or call_status_obj.is_completion_status:
                    logger.debug('Calling call status change xml process')
                    send_call_ticket_status_change(callobj)
                else:
                    logger.debug('Vendor key of call status/reason code not available')
    if auto_emails:
        ProcessAutoEmailsThread(callobj, auto_emails, '%d-%b-%Y', 'Asia/Kolkata').start()
    if callobj.queue and callobj.queue.is_on_call_support_enabled and callobj.status.is_on_call_creation_status:
        create_on_call_ticket(callobj)
    if callobj.tenant_id == 1 and callobj.status.is_completion_status and callobj.status != callobj.old_status:
        update_on_call_ticket(callobj)    
    if callobj.status.is_sla_calculation_applicable and not callobj.old_status.is_sla_calculation_applicable:
        process_sla(callobj)
    
post_save.connect(call_ticket_post_save_signal_receiver, sender = CallTicket)


def create_on_call_ticket(callobj):
    # Check for SO Number in reference number field to verify order is created already or not
    logger.debug('Create On Site Call Ticket Process Started')
    if callobj.queue.call_method:
        if callobj.queue.call_method == 2:
            url = callobj.queue.call_method_value
            auth = 'Basic ' + settings.INTERNAL_API_CALL_KEY
            logger.debug('Calling External API: ' + url)
            values = {  "so_num": callobj.get_so_num(),
                        "branch_code": callobj.branch.branch_code,
                        "end_user_name": callobj.end_user_name,
                        "end_user_email": callobj.end_user_email,
                        "issue_details": callobj.issue_details,
                        "created_time": callobj.created_time,
                        "machine_serial_num": callobj.get_machine_serial_num()              
                    }
            headers =  {'content-type' : 'application/json', 'Authorization': auth}
            response = requests.post(url, headers=headers, data=json.dumps(values, default=str))
            output_json = json.dumps(response.json())
            logger.debug('Create On Site Call Ticket Process Completed')
        if callobj.queue.call_method == 1:
            logger.debug('Calling Internal DB')
            if not CallTicket.objects.filter(reference_number = callobj.get_so_num()).exists():
                if callobj.branch and callobj.branch.branch_code:
                    newcustomerobj = Customer.objects.filter(customer_code = callobj.branch.branch_code).first()
                    if newcustomerobj:
                        logger.debug('Call Ticket Creation Started')
                        tenantObj = Tenant.objects.get(pk = newcustomerobj.branch.tenant.id)
                        vendorobj = Vendor.objects.get(pk = newcustomerobj.branch.vendor.id)
                        callstatusobj = CallStatus.objects.filter(tenant = tenantObj, is_initial_status = True).first()
                        ticketTypeObj = TicketType.objects.filter(tenant = tenantObj, is_initial_status = True).first()
                        calltype = CallType.objects.filter(tenant = tenantObj, vendor = vendorobj, name='On call').first()
                        newcallobj = CallTicket(tenant = tenantObj, vendor = vendorobj, ticket_type = ticketTypeObj, status = callstatusobj, customer_name = newcustomerobj.name, customer_phone = newcustomerobj.phone, customer_email = newcustomerobj.email, customer_address = newcustomerobj.address, end_user_name = callobj.end_user_name, end_user_email = callobj.end_user_email, issue_details = callobj.issue_details, vendor_crm_ticket_time = callobj.created_time, reference_number = callobj.get_so_num(), customer = newcustomerobj, is_auto_appointment = newcustomerobj.is_auto_appointment_allowed, branch = newcustomerobj.branch, call_type = calltype)
                        if newcustomerobj.severity_based_sla_applicable:
                            severity_level_for_customer= SeverityLevel.objects.filter(is_active = True, customer = newcustomerobj).first()
                            if severity_level_for_customer:
                                newcallobj.severity_level = severity_level_for_customer
                        newcallobj.save()
                        logger.debug('New Call Ticket Created')
                        if callobj.get_machine_serial_num():
                            ticketMachineDetailsObj = TicketMachineDetails(ticket = newcallobj, serial_number = callobj.get_machine_serial_num())
                            ticketMachineDetailsObj.save()
                            logger.debug('New Ticket Machine Created')
                        ticketStatusTrackObj = TicketStatusTrack(ticket = newcallobj, notes ='New Call Ticket Created', new_status = callstatusobj, status_change_time = timezone.now())
                        logger.debug('Ticket Status Track Updated')
                        ticketStatusTrackObj.save()
                        logger.debug('Call Ticket Creation Completed')
                    else:
                        logger.error("Invalid Vendor Customer Code: [" + callobj.branch.branch_code + "]")
                        output_json = {"error": "invalid vendor customer code"}
                        return HttpResponse(json.dumps(output_json), content_type='application/json', status=401)
                else:
                    logger.error("Vendor Customer Code Is Empty For The Branch")
                    output_json = {"error": "Vendor Customer Code Is Empty For The Branch"}
                    return HttpResponse(json.dumps(output_json), content_type='application/json', status=401)
            else:
                output_json = {"error": "Ticket Already Exist"}
                
def update_on_call_ticket(callobj):
    logger.debug('Update On Site Call Ticket')
    if callobj.reference_number:
        parent_call_ticket_id = callobj.reference_number.strip()
        url = ''
        call_type = ''
        if callobj.customer:
            if callobj.customer.call_method:
                if callobj.customer.call_method == 1:
                    call_type = 'DB'
                elif callobj.customer.call_method == 2:
                    call_type = 'API'
                    url = callobj.customer.call_method_value
            elif callobj.customer.customer_group and callobj.customer.customer_group.call_method:
                if callobj.customer.customer_group.call_method == 1:
                    call_type = 'DB'
                elif callobj.customer.customer_group.call_method == 2:
                    call_type = 'API'
                    url = callobj.customer.customer_group.call_method_value
        if call_type == '':
            logger.error("Unable to find call type method for the customer")
            output_json = {"error": "Unable to find call type method for the customer"}
            return HttpResponse(json.dumps(output_json), content_type='application/json', status=400)
        if call_type == 'API':
            logger.debug('Calling External API: ' + url)
            values = {  
                        "ref_num": parent_call_ticket_id 
                    }
            auth = 'Basic ' + settings.INTERNAL_API_CALL_KEY
            headers =  {'content-type' : 'application/json', 'Authorization': auth}
            response = requests.post(url, headers=headers, data=json.dumps(values, default=str))
            output_json = json.dumps(response.json())
            logger.debug('Calling External API Job Completed')
        if call_type == 'DB':
            logger.debug('Calling Internal DB')
            parent_call_ticket_id = parent_call_ticket_id[2:]
            if parent_call_ticket_id.isdigit():
                branchObj = Branch.objects.filter(branch_code = callobj.customer.customer_code).first()
                if branchObj:
                    tenantObj = Tenant.objects.get(pk = branchObj.tenant.pk)
                    parent_call_ticket = CallTicket.objects.filter(pk = parent_call_ticket_id, tenant = tenantObj).first()
                    if parent_call_ticket:
                        logger.debug('Updating Call Ticket: [' + str(parent_call_ticket_id) + ']')
                        statusobj = CallStatus.objects.filter(tenant = tenantObj, is_completion_status = True).first()
                        parent_call_ticket.old_status = parent_call_ticket.status
                        parent_call_ticket.status = statusobj
                        ticketStatusTrackObj = TicketStatusTrack(ticket = parent_call_ticket, notes ='Updated by Automated Process', new_status = statusobj, status_change_time = timezone.now())
                        ticketStatusTrackObj.save()
                        parent_call_ticket.save()
                        logger.debug('Call Ticket Updated')
                        logger.debug('Call Ticket Status Track Updated')
                        ticketClosureNotesObj = TicketClosureNotes.objects.filter(ticket = callobj).first()
                        if ticketClosureNotesObj:
                            ticketClosureNotesParentObj = TicketClosureNotes(ticket = parent_call_ticket, observation = ticketClosureNotesObj.observation, action_taken = ticketClosureNotesObj.action_taken)
                            ticketClosureNotesParentObj.save()
                            logger.debug('Engineer Feedback Updated')
                        audit_json = []
                        make_audit_entry = False
                        if parent_call_ticket.old_status != parent_call_ticket.status:
                            make_audit_entry = True
                            audit_json.append({"table_name":"CallTicket", "pk":parent_call_ticket.pk, "display_name":"Status", "field_name":"status", "old_value":parent_call_ticket.old_status.name, "new_value":parent_call_ticket.status.name})
                        if make_audit_entry:
                            change_audit = TicketChangesAudit(ticket = parent_call_ticket, audit_json = json.dumps(audit_json), updated_time = timezone.now())
                            change_audit.save()
                            logger.debug('Call Ticket Audit Updated')
                        logger.debug('Update Call Ticket Completed')
                    else:
                        logger.error("Parent Call Ticket Not Available")
                        output_json = {"error": "Parent Call Ticket Not Available"}
                        return HttpResponse(json.dumps(output_json), content_type='application/json', status=400)
                else:
                    logger.error("Branch Not Found For The Vendor Customer Code: [" + callobj.customer.customer_code + "]")
                    output_json = {"error": "invalid call ticket reference number"}
                    return HttpResponse(json.dumps(output_json), content_type='application/json', status=400)
            else:
                logger.error("Invalid Call Ticket Reference Number: [" + str(parent_call_ticket_id) + "]")
                output_json = {"error": "invalid call ticket reference number"}
                return HttpResponse(json.dumps(output_json), content_type='application/json', status=400)


def process_sla(callobj):
    response_time = callobj.get_response_time()
    applicable_response_time = callobj.get_applicable_response_time()
    resolution_time = callobj.get_resolution_time()
    applicable_resolution_time = callobj.get_applicable_resolution_time()
    # print ('TIMES:', response_time, applicable_response_time, resolution_time, applicable_resolution_time)
    is_response_sla_met = None
    is_resolution_sla_met = None
    if response_time and applicable_response_time:
        is_response_sla_met = True
        if response_time > applicable_response_time:
            is_response_sla_met = False
    if resolution_time and applicable_resolution_time:
        is_resolution_sla_met = True
        if resolution_time > applicable_resolution_time:
            is_resolution_sla_met = False
    callobj.is_response_sla_met = is_response_sla_met
    callobj.is_resolution_sla_met = is_resolution_sla_met
    callobj.save()

class ProcessAutoEmailsThread(threading.Thread):

    def __init__(self, callobj, auto_emails, date_format, time_zone):
        self.callobj = callobj
        self.auto_emails = auto_emails
        self.date_format = date_format
        self.time_zone = time_zone
        super(ProcessAutoEmailsThread, self).__init__()

    def run(self):
        process_auto_emails(self.callobj, self.auto_emails, self.date_format, self.time_zone)


def process_auto_emails(callobj, auto_emails, date_format, time_zone):
    for auto_email in auto_emails:
        to_list = []
        cc_list = []
        bcc_list = []
        if auto_email.trigger == auto_email.TRIGGER_CALL_CREATE:
            cc_list.append(settings.EMAIL_LISTENER)
        if auto_email.send_to_customer:
            to_list.append(callobj.customer_email)
        for recepient in auto_email.autoemailrecepients_set.all():
            vendor_emails = None
            if recepient.area_type == AutoEmailRecepients.AREA_TYPE_COUNTRY:
                if callobj.branch:
                    vendor_emails = CountryVendorEmail.objects.filter(tenant = auto_email.tenant, country = callobj.branch.state.country, vendor = callobj.vendor, recepient_type = recepient.recepient_type)
            elif recepient.area_type == AutoEmailRecepients.AREA_TYPE_STATE:
                if callobj.branch:
                    vendor_emails = StateVendorEmail.objects.filter(tenant = auto_email.tenant, state = callobj.branch.state, vendor = callobj.vendor, recepient_type = recepient.recepient_type)
            elif recepient.area_type == AutoEmailRecepients.AREA_TYPE_REGION:
                if callobj.branch:
                    vendor_emails = RegionVendorEmail.objects.filter(region = callobj.branch.region, vendor = callobj.vendor, recepient_type = recepient.recepient_type)
            elif recepient.area_type == AutoEmailRecepients.AREA_TYPE_BRANCH:
                if callobj.branch:
                    vendor_emails = BranchVendorEmail.objects.filter(branch = callobj.branch, vendor = callobj.vendor, recepient_type = recepient.recepient_type)
            elif recepient.area_type == AutoEmailRecepients.AREA_TYPE_QUEUE:
                if callobj.queue:    
                    vendor_emails = QueueVendorEmail.objects.filter(queue = callobj.queue, vendor = callobj.vendor, recepient_type = recepient.recepient_type)
            if vendor_emails:
                for vendor_email in vendor_emails:
                    if recepient.recepient_position == AutoEmailRecepients.RECEIPIENT_POSITION_TO:
                        if not vendor_email.email in to_list:
                            to_list.append(vendor_email.email)
                    elif recepient.recepient_position == AutoEmailRecepients.RECEIPIENT_POSITION_CC:
                        if not vendor_email.email in cc_list:
                            cc_list.append(vendor_email.email)
                    elif recepient.recepient_position == AutoEmailRecepients.RECEIPIENT_POSITION_BCC:
                        if not vendor_email.email in bcc_list:
                            bcc_list.append(vendor_email.email)
        from_email = settings.EMAIL_FROM
        is_attachment_required = False
        filename = None
        filecontent = None
        filetype = None
        if not callobj.is_paper_upload_of_so:
            if auto_email.attachment == AutoEmail.ATTACHMENT_TYPE_SO_REPORT:
                if callobj.vendor.pk == 1 or callobj.vendor.pk == 4:
                    is_attachment_required = True
                    filetype = 'application/pdf'
                    filename = callobj.vendor_crm_ticket_num + '.pdf'
                    page1_url = settings.BASE_URL + reverse('get_service_report', kwargs={'ticket_id':callobj.pk, 'page_num':'1'})
                    page1_filename = settings.TEMP_DIR + '/' + callobj.vendor_crm_ticket_num + '_p1.pdf'
                    create_pdf_document(page1_url, page1_filename)
                    page2_url = settings.BASE_URL + reverse('get_service_report', kwargs={'ticket_id':callobj.pk, 'page_num':'2'})
                    page2_filename = settings.TEMP_DIR + '/' + callobj.vendor_crm_ticket_num + '_p2.pdf'
                    create_pdf_document(page2_url, page2_filename)
                    merge_pdf_files(settings.UPLOADS_DIR + '/' + filename, [page1_filename, page2_filename])
                    ticket_document = TicketDocument(ticket = callobj, document_name = 'SO Report', document_url = '/file/' + filename)
                    ticket_document.save()
                    with open(settings.UPLOADS_DIR + '/' + filename, 'rb') as fileobj:
                        filecontent = fileobj.read()
            send_email_message(from_email, to_list, cc_list, bcc_list, transform_email_content(callobj, auto_email.email_subject, date_format, time_zone), transform_email_content(callobj, auto_email.email_body, date_format, time_zone), is_attachment_required, filename, filecontent, filetype)
            receivers_email_list = set(to_list + cc_list + bcc_list)
            create_notification_for_auto_email(receivers_email_list, transform_email_content(callobj, auto_email.email_subject, date_format, time_zone), transform_email_content(callobj, auto_email.email_body, date_format, time_zone))
        
def create_notification_for_auto_email(receivers_email_list, title, message):
    receiver_obj_list = []
    for email in receivers_email_list:
        adminObj = Administrator.objects.filter(email = email).first()
        if adminObj:
            # hcmsObj =  HCMSUser.objects.get(pk = adminObj.pk)
            receiver_obj_list.append(adminObj)
    create_notification(receiver_obj_list, title, message, custom_sender='Auto Email')

        
#def transform_email_content(callobj, content, date_format, time_zone):
    #return content.replace('$SO_NUMBER$', callobj.get_so_num()).replace('$MACHINE_SERIAL_NUMBER$', callobj.get_machine_serial_num()).replace('$ENGINEER_NAME$', callobj.get_engineer_name()).replace('$APPOINTMENT_DATE$', get_date_disp_value(callobj.appointment_check_date, date_format, time_zone)).replace('$CREATED_DATE$', get_date_disp_value(callobj.get_created_time(), date_format, time_zone)).replace('$CUSTOMER_PHONES$', callobj.get_customer_phones()).replace('$FIXED_DATE$', get_date_disp_value(callobj.get_fixed_date(), date_format, time_zone)).replace('$BRANCH$', callobj.branch.name).replace('$CALL_STATUS$', callobj.status.name).replace('$CUSTOMER_NAME$', callobj.customer_name).replace('$ASSET_TYPE$', callobj.get_machine_type()).replace('$ASSET_MODEL$', callobj.get_machine_model()).replace('$END_USER_NAME$', callobj.get_end_user_name()).replace('$END_USER_EMAIL$', callobj.get_end_user_email())


class HomePage(AdminTemplateView):
    template_name = 'admin_home.html'

    def get_context_data(self, **kwargs):
        context = super(HomePage,self).get_context_data(**kwargs)
        context['last_6_months_list'] = cache.get('last_6_months_list', ['', '', '', '', '', ''])
        context['last_dashboard_refresh_time'] = cache.get('last_dashboard_refresh_time', '')
        app_user = HCMSUser.objects.get(pk = self.request.user.pk)
        user_vendors = self.request.session['user_vendors']
        user_branches = self.request.session['user_branches']
        user_customers = self.request.session['user_customers']
        user_queues = self.request.session['user_queues']
        suffix = '_' + str(app_user.tenant.pk)
        month_0_resolution_sla_met = 0
        month_0_response_sla_met = 0
        month_1_resolution_sla_met = 0
        month_1_response_sla_met = 0
        month_2_resolution_sla_met = 0
        month_2_response_sla_met = 0
        month_3_resolution_sla_met = 0
        month_3_response_sla_met = 0
        month_4_resolution_sla_met = 0
        month_4_response_sla_met = 0
        month_5_resolution_sla_met = 0
        month_5_response_sla_met = 0
        month_0_resolution_sla_failed = 0
        month_0_response_sla_failed = 0
        month_1_resolution_sla_failed = 0
        month_1_response_sla_failed = 0
        month_2_resolution_sla_failed = 0
        month_2_response_sla_failed = 0
        month_3_resolution_sla_failed = 0
        month_3_response_sla_failed = 0
        month_4_resolution_sla_failed = 0
        month_4_response_sla_failed = 0
        month_5_resolution_sla_failed = 0
        month_5_response_sla_failed = 0
        if len(user_vendors) == 0 and len(user_branches) == 0 and len(user_customers) == 0 and len(user_queues) == 0:
            month_0_resolution_sla_met = cache.get('month_0_resolution_sla_met' + suffix, 0)
            month_0_response_sla_met = cache.get('month_0_response_sla_met' + suffix, 0)
            month_0_resolution_sla_failed = cache.get('month_0_resolution_sla_failed' + suffix, 0)
            month_0_response_sla_failed = cache.get('month_0_response_sla_failed' + suffix, 0)
            month_1_resolution_sla_met = cache.get('month_1_resolution_sla_met' + suffix, 0)
            month_1_response_sla_met = cache.get('month_1_response_sla_met' + suffix, 0)
            month_1_resolution_sla_failed = cache.get('month_1_resolution_sla_failed' + suffix, 0)
            month_1_response_sla_failed = cache.get('month_1_response_sla_failed' + suffix, 0)
            month_2_resolution_sla_met = cache.get('month_2_resolution_sla_met' + suffix, 0)
            month_2_response_sla_met = cache.get('month_2_response_sla_met' + suffix, 0)
            month_2_resolution_sla_failed = cache.get('month_2_resolution_sla_failed' + suffix, 0)
            month_2_response_sla_failed = cache.get('month_2_response_sla_failed' + suffix, 0)
            month_3_resolution_sla_met = cache.get('month_3_resolution_sla_met' + suffix, 0)
            month_3_response_sla_met = cache.get('month_3_response_sla_met' + suffix, 0)
            month_3_resolution_sla_failed = cache.get('month_3_resolution_sla_failed' + suffix, 0)
            month_3_response_sla_failed = cache.get('month_3_response_sla_failed' + suffix, 0)
            month_4_resolution_sla_met = cache.get('month_4_resolution_sla_met' + suffix, 0)
            month_4_response_sla_met = cache.get('month_4_response_sla_met' + suffix, 0)
            month_4_resolution_sla_failed = cache.get('month_4_resolution_sla_failed' + suffix, 0)
            month_4_response_sla_failed = cache.get('month_4_response_sla_failed' + suffix, 0)
            month_5_resolution_sla_met = cache.get('month_5_resolution_sla_met' + suffix, 0)
            month_5_response_sla_met = cache.get('month_5_response_sla_met' + suffix, 0)
            month_5_resolution_sla_failed = cache.get('month_5_resolution_sla_failed' + suffix, 0)
            month_5_response_sla_failed = cache.get('month_5_response_sla_failed' + suffix, 0)
        else:
            if len(user_queues) > 0:
                for queue in user_queues:
                    queue_suffix = suffix + '_' + str(queue.pk)
                    month_0_resolution_sla_met += cache.get('month_0_resolution_sla_met' + queue_suffix, 0)
                    month_0_response_sla_met += cache.get('month_0_response_sla_met' + queue_suffix, 0)
                    month_0_resolution_sla_failed += cache.get('month_0_resolution_sla_failed' + queue_suffix, 0)
                    month_0_response_sla_failed += cache.get('month_0_response_sla_failed' + queue_suffix, 0)
                    month_1_resolution_sla_met += cache.get('month_1_resolution_sla_met' + queue_suffix, 0)
                    month_1_response_sla_met += cache.get('month_1_response_sla_met' + queue_suffix, 0)
                    month_1_resolution_sla_failed += cache.get('month_1_resolution_sla_failed' + queue_suffix, 0)
                    month_1_response_sla_failed += cache.get('month_1_response_sla_failed' + queue_suffix, 0)
                    month_2_resolution_sla_met += cache.get('month_2_resolution_sla_met' + queue_suffix, 0)
                    month_2_response_sla_met += cache.get('month_2_response_sla_met' + queue_suffix, 0)
                    month_2_resolution_sla_failed += cache.get('month_2_resolution_sla_failed' + queue_suffix, 0)
                    month_2_response_sla_failed += cache.get('month_2_response_sla_failed' + queue_suffix, 0)
                    month_3_resolution_sla_met += cache.get('month_3_resolution_sla_met' + queue_suffix, 0)
                    month_3_response_sla_met += cache.get('month_3_response_sla_met' + queue_suffix, 0)
                    month_3_resolution_sla_failed += cache.get('month_3_resolution_sla_failed' + queue_suffix, 0)
                    month_3_response_sla_failed += cache.get('month_3_response_sla_failed' + queue_suffix, 0)
                    month_4_resolution_sla_met += cache.get('month_4_resolution_sla_met' + queue_suffix, 0)
                    month_4_response_sla_met += cache.get('month_4_response_sla_met' + queue_suffix, 0)
                    month_4_resolution_sla_failed += cache.get('month_4_resolution_sla_failed' + queue_suffix, 0)
                    month_4_response_sla_failed += cache.get('month_4_response_sla_failed' + queue_suffix, 0)
                    month_5_resolution_sla_met += cache.get('month_5_resolution_sla_met' + queue_suffix, 0)
                    month_5_response_sla_met += cache.get('month_5_response_sla_met' + queue_suffix, 0)
                    month_5_resolution_sla_failed += cache.get('month_5_resolution_sla_failed' + queue_suffix, 0)
                    month_5_response_sla_failed += cache.get('month_5_response_sla_failed' + queue_suffix, 0)
            elif len(user_customers) > 0:
                for customer in user_customers:
                    customer_suffix = suffix + '_' + str(customer.branch.vendor.pk) + '_' + str(customer.branch.pk) + '_' + str(customer.pk)
                    month_0_resolution_sla_met += cache.get('month_0_resolution_sla_met' + customer_suffix, 0)
                    month_0_response_sla_met += cache.get('month_0_response_sla_met' + customer_suffix, 0)
                    month_0_resolution_sla_failed += cache.get('month_0_resolution_sla_failed' + customer_suffix, 0)
                    month_0_response_sla_failed += cache.get('month_0_response_sla_failed' + customer_suffix, 0)
                    month_1_resolution_sla_met += cache.get('month_1_resolution_sla_met' + customer_suffix, 0)
                    month_1_response_sla_met += cache.get('month_1_response_sla_met' + customer_suffix, 0)
                    month_1_resolution_sla_failed += cache.get('month_1_resolution_sla_failed' + customer_suffix, 0)
                    month_1_response_sla_failed += cache.get('month_1_response_sla_failed' + customer_suffix, 0)
                    month_2_resolution_sla_met += cache.get('month_2_resolution_sla_met' + customer_suffix, 0)
                    month_2_response_sla_met += cache.get('month_2_response_sla_met' + customer_suffix, 0)
                    month_2_resolution_sla_failed += cache.get('month_2_resolution_sla_failed' + customer_suffix, 0)
                    month_2_response_sla_failed += cache.get('month_2_response_sla_failed' + customer_suffix, 0)
                    month_3_resolution_sla_met += cache.get('month_3_resolution_sla_met' + customer_suffix, 0)
                    month_3_response_sla_met += cache.get('month_3_response_sla_met' + customer_suffix, 0)
                    month_3_resolution_sla_failed += cache.get('month_3_resolution_sla_failed' + customer_suffix, 0)
                    month_3_response_sla_failed += cache.get('month_3_response_sla_failed' + customer_suffix, 0)
                    month_4_resolution_sla_met += cache.get('month_4_resolution_sla_met' + customer_suffix, 0)
                    month_4_response_sla_met += cache.get('month_4_response_sla_met' + customer_suffix, 0)
                    month_4_resolution_sla_failed += cache.get('month_4_resolution_sla_failed' + customer_suffix, 0)
                    month_4_response_sla_failed += cache.get('month_4_response_sla_failed' + customer_suffix, 0)
                    month_5_resolution_sla_met += cache.get('month_5_resolution_sla_met' + customer_suffix, 0)
                    month_5_response_sla_met += cache.get('month_5_response_sla_met' + customer_suffix, 0)
                    month_5_resolution_sla_failed += cache.get('month_5_resolution_sla_failed' + customer_suffix, 0)
                    month_5_response_sla_failed += cache.get('month_5_response_sla_failed' + customer_suffix, 0)
            elif len(user_branches) > 0:
                for branch in user_branches:
                    branch_suffix = suffix + '_' + str(branch.vendor.pk) + '_' + str(branch.pk)
                    month_0_resolution_sla_met += cache.get('month_0_resolution_sla_met' + branch_suffix, 0)
                    month_0_response_sla_met += cache.get('month_0_response_sla_met' + branch_suffix, 0)
                    month_0_resolution_sla_failed += cache.get('month_0_resolution_sla_failed' + branch_suffix, 0)
                    month_0_response_sla_failed += cache.get('month_0_response_sla_failed' + branch_suffix, 0)
                    month_1_resolution_sla_met += cache.get('month_1_resolution_sla_met' + branch_suffix, 0)
                    month_1_response_sla_met += cache.get('month_1_response_sla_met' + branch_suffix, 0)
                    month_1_resolution_sla_failed += cache.get('month_1_resolution_sla_failed' + branch_suffix, 0)
                    month_1_response_sla_failed += cache.get('month_1_response_sla_failed' + branch_suffix, 0)
                    month_2_resolution_sla_met += cache.get('month_2_resolution_sla_met' + branch_suffix, 0)
                    month_2_response_sla_met += cache.get('month_2_response_sla_met' + branch_suffix, 0)
                    month_2_resolution_sla_failed += cache.get('month_2_resolution_sla_failed' + branch_suffix, 0)
                    month_2_response_sla_failed += cache.get('month_2_response_sla_failed' + branch_suffix, 0)
                    month_3_resolution_sla_met += cache.get('month_3_resolution_sla_met' + branch_suffix, 0)
                    month_3_response_sla_met += cache.get('month_3_response_sla_met' + branch_suffix, 0)
                    month_3_resolution_sla_failed += cache.get('month_3_resolution_sla_failed' + branch_suffix, 0)
                    month_3_response_sla_failed += cache.get('month_3_response_sla_failed' + branch_suffix, 0)
                    month_4_resolution_sla_met += cache.get('month_4_resolution_sla_met' + branch_suffix, 0)
                    month_4_response_sla_met += cache.get('month_4_response_sla_met' + branch_suffix, 0)
                    month_4_resolution_sla_failed += cache.get('month_4_resolution_sla_failed' + branch_suffix, 0)
                    month_4_response_sla_failed += cache.get('month_4_response_sla_failed' + branch_suffix, 0)
                    month_5_resolution_sla_met += cache.get('month_5_resolution_sla_met' + branch_suffix, 0)
                    month_5_response_sla_met += cache.get('month_5_response_sla_met' + branch_suffix, 0)
                    month_5_resolution_sla_failed += cache.get('month_5_resolution_sla_failed' + branch_suffix, 0)
                    month_5_response_sla_failed += cache.get('month_5_response_sla_failed' + branch_suffix, 0)
            elif len(user_vendors) > 0:
                for vendor in user_vendors:
                    vendor_suffix = suffix + '_' + str(vendor.pk)
                    month_0_resolution_sla_met += cache.get('month_0_resolution_sla_met' + vendor_suffix, 0)
                    month_0_response_sla_met += cache.get('month_0_response_sla_met' + vendor_suffix, 0)
                    month_0_resolution_sla_failed += cache.get('month_0_resolution_sla_failed' + vendor_suffix, 0)
                    month_0_response_sla_failed += cache.get('month_0_response_sla_failed' + vendor_suffix, 0)
                    month_1_resolution_sla_met += cache.get('month_1_resolution_sla_met' + vendor_suffix, 0)
                    month_1_response_sla_met += cache.get('month_1_response_sla_met' + vendor_suffix, 0)
                    month_1_resolution_sla_failed += cache.get('month_1_resolution_sla_failed' + vendor_suffix, 0)
                    month_1_response_sla_failed += cache.get('month_1_response_sla_failed' + vendor_suffix, 0)
                    month_2_resolution_sla_met += cache.get('month_2_resolution_sla_met' + vendor_suffix, 0)
                    month_2_response_sla_met += cache.get('month_2_response_sla_met' + vendor_suffix, 0)
                    month_2_resolution_sla_failed += cache.get('month_2_resolution_sla_failed' + vendor_suffix, 0)
                    month_2_response_sla_failed += cache.get('month_2_response_sla_failed' + vendor_suffix, 0)
                    month_3_resolution_sla_met += cache.get('month_3_resolution_sla_met' + vendor_suffix, 0)
                    month_3_response_sla_met += cache.get('month_3_response_sla_met' + vendor_suffix, 0)
                    month_3_resolution_sla_failed += cache.get('month_3_resolution_sla_failed' + vendor_suffix, 0)
                    month_3_response_sla_failed += cache.get('month_3_response_sla_failed' + vendor_suffix, 0)
                    month_4_resolution_sla_met += cache.get('month_4_resolution_sla_met' + vendor_suffix, 0)
                    month_4_response_sla_met += cache.get('month_4_response_sla_met' + vendor_suffix, 0)
                    month_4_resolution_sla_failed += cache.get('month_4_resolution_sla_failed' + vendor_suffix, 0)
                    month_4_response_sla_failed += cache.get('month_4_response_sla_failed' + vendor_suffix, 0)
                    month_5_resolution_sla_met += cache.get('month_5_resolution_sla_met' + vendor_suffix, 0)
                    month_5_response_sla_met += cache.get('month_5_response_sla_met' + vendor_suffix, 0)
                    month_5_resolution_sla_failed += cache.get('month_5_resolution_sla_failed' + vendor_suffix, 0)
                    month_5_response_sla_failed += cache.get('month_5_response_sla_failed' + vendor_suffix, 0)
        context['month_0_resolution_sla_met'] = month_0_resolution_sla_met
        context['month_0_response_sla_met'] = month_0_response_sla_met
        context['month_0_resolution_sla_failed'] = month_0_resolution_sla_failed
        context['month_0_response_sla_failed'] = month_0_response_sla_failed
        context['month_1_resolution_sla_met'] = month_1_resolution_sla_met
        context['month_1_response_sla_met'] = month_1_response_sla_met
        context['month_1_resolution_sla_failed'] = month_1_resolution_sla_failed
        context['month_1_response_sla_failed'] = month_1_response_sla_failed
        context['month_2_resolution_sla_met'] = month_2_resolution_sla_met
        context['month_2_response_sla_met'] = month_2_response_sla_met
        context['month_2_resolution_sla_failed'] = month_2_resolution_sla_failed
        context['month_2_response_sla_failed'] = month_2_response_sla_failed
        context['month_3_resolution_sla_met'] = month_3_resolution_sla_met
        context['month_3_response_sla_met'] = month_3_response_sla_met
        context['month_3_resolution_sla_failed'] = month_3_resolution_sla_failed
        context['month_3_response_sla_failed'] = month_3_response_sla_failed
        context['month_4_resolution_sla_met'] = month_4_resolution_sla_met
        context['month_4_response_sla_met'] = month_4_response_sla_met
        context['month_4_resolution_sla_failed'] = month_4_resolution_sla_failed
        context['month_4_response_sla_failed'] = month_4_response_sla_failed
        context['month_5_resolution_sla_met'] = month_5_resolution_sla_met
        context['month_5_response_sla_met'] = month_5_response_sla_met
        context['month_5_resolution_sla_failed'] = month_5_resolution_sla_failed
        context['month_5_response_sla_failed'] = month_5_response_sla_failed
        status_list = CallStatus.objects.filter(tenant = app_user.tenant, is_active = True).exclude(is_completion_status = True).order_by('id')
        open_calls = CallTicket.objects.filter(status__in = status_list)
        user_vendors = self.request.session['user_vendors']
        user_branches = self.request.session['user_branches']
        has_multiple_vendors = True
        if len(user_vendors) == 0:
            user_vendors = Vendor.objects.filter(is_active = True).order_by('name')
        if len(user_vendors) == 1:
            has_multiple_vendors = False
        context['has_multiple_vendors'] = has_multiple_vendors
        if len(user_vendors) > 0:
            open_calls = open_calls.filter(vendor__in = user_vendors)
        if len(user_branches) > 0:
            open_calls = open_calls.filter(branch__in = user_branches)
        if len(user_customers) > 0:
            open_calls = open_calls.filter(customer__in = user_customers)
        #print ('open_calls:', open_calls)
        open_status_list = []
        status_count_list = []
        for status in status_list:
            open_status_list.append(status.name)
            status_call_list = get_call_list(open_calls, status)
            status_count_list.append(status_call_list.count())
        context['open_status_list'] = open_status_list
        context['status_count_list'] = status_count_list
        asset_status_list = AssetStatus.objects.filter(tenant = app_user.tenant, is_active = True).order_by('id')
        final_assets = Machine.objects.all()
        asset_status_name_list = []
        asset_status_name_count_list = []
        for status in asset_status_list:
            asset_status_name_list.append(status.name)
            final_assets.filter(status = status)
            assets_list = get_asset_list(final_assets, status)
            asset_status_name_count_list.append(assets_list.count())
        context['asset_status_name_list'] = asset_status_name_list
        context['asset_status_name_count_list'] = asset_status_name_count_list
        has_multiple_branches = True
        default_branch_list = app_user.access_branches.filter(tenant = app_user.tenant, is_active = True).order_by('name')
        if len(user_branches) == 0:
            default_branch_list = Branch.objects.filter(tenant = app_user.tenant, is_active = True).order_by('name')
        if len(user_branches) == 1:
            has_multiple_branches = False
        vendor_sla_data_map = {}
        vendor_branches_map = {}
        #cgcode_start
        vendor_customer_groups_map = {}
        #cgcode_end
        if has_multiple_vendors:
            vendor_names_list = []
            vendor_data_map = {}
            for vendor in user_vendors:
                vendor_suffix = suffix + '_' + str(vendor.pk)
                vendor_names_list.append([vendor.pk, vendor.name])
                vendor_status_count_list = []
                vendor_asset_count_list = []
                vendor_sla_count_list = [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]]
                for status in status_list:
                    vendor_status_call_list = get_call_list(open_calls, status, vendor)
                    vendor_status_count_list.append(vendor_status_call_list.count())
                for asset_status in asset_status_list:
                    vendor_asset_list = get_asset_list(final_assets, asset_status, vendor)
                    vendor_asset_count_list.append(vendor_asset_list.count())
                vendor_data_map[vendor.pk] = [vendor_status_count_list, vendor_asset_count_list]
                branch_list = app_user.access_branches.filter(vendor = vendor, is_active = True).order_by('name')
                if len(user_branches) == 0:
                    vendor_sla_count_list[0][0] = cache.get('month_0_resolution_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[0][1] = cache.get('month_1_resolution_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[0][2] = cache.get('month_2_resolution_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[0][3] = cache.get('month_3_resolution_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[0][4] = cache.get('month_4_resolution_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[0][5] = cache.get('month_5_resolution_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[1][0] = cache.get('month_0_resolution_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[1][1] = cache.get('month_1_resolution_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[1][2] = cache.get('month_2_resolution_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[1][3] = cache.get('month_3_resolution_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[1][4] = cache.get('month_4_resolution_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[1][5] = cache.get('month_5_resolution_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[2][0] = cache.get('month_0_response_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[2][1] = cache.get('month_1_response_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[2][2] = cache.get('month_2_response_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[2][3] = cache.get('month_3_response_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[2][4] = cache.get('month_4_response_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[2][5] = cache.get('month_5_response_sla_met' + vendor_suffix, 0)
                    vendor_sla_count_list[3][0] = cache.get('month_0_response_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[3][1] = cache.get('month_1_response_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[3][2] = cache.get('month_2_response_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[3][3] = cache.get('month_3_response_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[3][4] = cache.get('month_4_response_sla_failed' + vendor_suffix, 0)
                    vendor_sla_count_list[3][5] = cache.get('month_5_response_sla_failed' + vendor_suffix, 0)
                    branch_list = Branch.objects.filter(vendor = vendor, is_active = True).order_by('name')
                else:
                    for branch in user_branches:
                        branch_suffix = suffix + '_' + str(branch.vendor.pk) + '_' + str(branch.pk)
                        vendor_sla_count_list[0][0] += cache.get('month_0_resolution_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[0][1] += cache.get('month_1_resolution_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[0][2] += cache.get('month_2_resolution_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[0][3] += cache.get('month_3_resolution_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[0][4] += cache.get('month_4_resolution_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[0][5] += cache.get('month_5_resolution_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[1][0] += cache.get('month_0_resolution_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[1][1] += cache.get('month_1_resolution_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[1][2] += cache.get('month_2_resolution_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[1][3] += cache.get('month_3_resolution_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[1][4] += cache.get('month_4_resolution_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[1][5] += cache.get('month_5_resolution_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[2][0] += cache.get('month_0_response_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[2][1] += cache.get('month_1_response_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[2][2] += cache.get('month_2_response_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[2][3] += cache.get('month_3_response_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[2][4] += cache.get('month_4_response_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[2][5] += cache.get('month_5_response_sla_met' + branch_suffix, 0)
                        vendor_sla_count_list[3][0] += cache.get('month_0_response_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[3][1] += cache.get('month_1_response_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[3][2] += cache.get('month_2_response_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[3][3] += cache.get('month_3_response_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[3][4] += cache.get('month_4_response_sla_failed' + branch_suffix, 0)
                        vendor_sla_count_list[3][5] += cache.get('month_5_response_sla_failed' + branch_suffix, 0)
                vendor_sla_data_map[vendor.pk] = vendor_sla_count_list
                vendor_branch_list = []
                for branch in branch_list:
                    vendor_branch_list.append([branch.pk, branch.name])
                vendor_branches_map[vendor.pk] = vendor_branch_list
                #cgcode_start
                vendor_customer_group_list = []
                vendor_cg_list = vendor.customergroup_set.all()
                vendor_cg_list = vendor_cg_list.filter(is_active = True)
                for cg in vendor_cg_list:
                    group_pk = 'cg' + str(cg.pk)
                    vendor_customer_group_list.append([group_pk, cg.name])
                vendor_customer_groups_map[vendor.pk] = vendor_customer_group_list
                #cgcode_end
            context['vendor_names_list'] = vendor_names_list
            context['vendor_data_map'] = vendor_data_map
            #cgcode_start
            context['vendor_customer_groups_map'] = vendor_customer_groups_map
            #cgcode_end
        else:
            branch_list = app_user.access_branches.filter(vendor = user_vendors[0], is_active = True).order_by('name')
            if len(user_branches) == 0:
                branch_list = Branch.objects.filter(vendor = user_vendors[0], is_active = True).order_by('name')
            context['default_branch_names_list'] = branch_list
        context['vendor_sla_data_map'] = vendor_sla_data_map
        context['vendor_branches_map'] = vendor_branches_map
        #print ('vendor_sla_data_map:', vendor_sla_data_map)
        
        config_map = self.request.config_map
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'True':        
            branch_data_map = {}
            branch_sla_data_map = {}
            branch_customer_map = {}
            if not has_multiple_branches:
                customer_name_list = Customer.objects.filter(branch = user_branches[0]).order_by('name')
                context['default_customer_names_list'] = customer_name_list
            for branch in default_branch_list:
                branch_suffix = suffix + '_' + str(branch.vendor.pk) + '_' + str(branch.pk)
                branch_status_count_list = []
                branch_asset_count_list = []
                branch_sla_count_list = [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]]
                for status in status_list:
                    branch_status_call_list = get_call_list(open_calls, status, None, branch)
                    branch_status_count_list.append(branch_status_call_list.count())
                for asset_status in asset_status_list:
                    branch_asset_list = get_asset_list(final_assets, asset_status, None, branch)
                    branch_asset_count_list.append(branch_asset_list.count())
                branch_data_map[branch.pk] = [branch_status_count_list, branch_asset_count_list]
                branch_sla_count_list[0][0] = cache.get('month_0_resolution_sla_met' + branch_suffix, 0)
                branch_sla_count_list[0][1] = cache.get('month_1_resolution_sla_met' + branch_suffix, 0)
                branch_sla_count_list[0][2] = cache.get('month_2_resolution_sla_met' + branch_suffix, 0)
                branch_sla_count_list[0][3] = cache.get('month_3_resolution_sla_met' + branch_suffix, 0)
                branch_sla_count_list[0][4] = cache.get('month_4_resolution_sla_met' + branch_suffix, 0)
                branch_sla_count_list[0][5] = cache.get('month_5_resolution_sla_met' + branch_suffix, 0)
                branch_sla_count_list[1][0] = cache.get('month_0_resolution_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[1][1] = cache.get('month_1_resolution_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[1][2] = cache.get('month_2_resolution_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[1][3] = cache.get('month_3_resolution_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[1][4] = cache.get('month_4_resolution_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[1][5] = cache.get('month_5_resolution_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[2][0] = cache.get('month_0_response_sla_met' + branch_suffix, 0)
                branch_sla_count_list[2][1] = cache.get('month_1_response_sla_met' + branch_suffix, 0)
                branch_sla_count_list[2][2] = cache.get('month_2_response_sla_met' + branch_suffix, 0)
                branch_sla_count_list[2][3] = cache.get('month_3_response_sla_met' + branch_suffix, 0)
                branch_sla_count_list[2][4] = cache.get('month_4_response_sla_met' + branch_suffix, 0)
                branch_sla_count_list[2][5] = cache.get('month_5_response_sla_met' + branch_suffix, 0)
                branch_sla_count_list[3][0] = cache.get('month_0_response_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[3][1] = cache.get('month_1_response_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[3][2] = cache.get('month_2_response_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[3][3] = cache.get('month_3_response_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[3][4] = cache.get('month_4_response_sla_failed' + branch_suffix, 0)
                branch_sla_count_list[3][5] = cache.get('month_5_response_sla_failed' + branch_suffix, 0)
                branch_sla_data_map[branch.pk] = branch_sla_count_list
                customer_list = Customer.objects.filter(branch = branch).order_by('name')
                branch_customer_list = []
                branch_customer_group_list = []
                for cusobj in customer_list:
                    if not cusobj.customer_group:
                        branch_customer_list.append([cusobj.pk, cusobj.name])
                    else:
                        branch_customer_group_list.append(cusobj.customer_group)
                branch_customer_group_list = list(set(branch_customer_group_list))  
                for obj in branch_customer_group_list:
                    group_pk = 'cg' + str(obj.pk)
                    branch_customer_list.append([group_pk, obj.name])
                branch_customer_map[branch.pk] = branch_customer_list  
            context['branch_data_map'] = branch_data_map
            context['branch_sla_data_map'] = branch_sla_data_map
            context['branch_customer_map'] = branch_customer_map
            default_branch_id_list = []
            for obj in default_branch_list:
                default_branch_id_list.append(obj.pk)
            default_customer_list = Customer.objects.filter(branch__in = default_branch_id_list).order_by('name')
            if self.request.session['customer_admin']:
                has_multiple_customers = True
                context['default_customer_names_list'] = user_customers
                default_customer_list = user_customers
                if len(user_customers) == 1:
                    has_multiple_customers = False
                    context['customer_pk'] = user_customers[0].pk
                context['has_multiple_customers'] = has_multiple_customers    
            customer_data_map = {}
            customer_sla_data_map = {}
            for customer in default_customer_list:
                customer_suffix = suffix + '_' + str(customer.branch.vendor.pk) + '_' + str(customer.branch.pk) + '_' + str(customer.pk)
                customer_status_count_list = []
                customer_asset_count_list = []
                customer_sla_count_list = [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]]
                for status in status_list:
                    customer_status_call_list = get_call_list(open_calls, status, None, None, customer)
                    customer_status_count_list.append(customer_status_call_list.count())
                for asset_status in asset_status_list:
                    customer_asset_list = get_asset_list(final_assets, asset_status, None, None, customer)
                    customer_asset_count_list.append(customer_asset_list.count())                    
                customer_data_map[customer.pk] = [customer_status_count_list, customer_asset_count_list]
                customer_sla_count_list[0][0] = cache.get('month_0_resolution_sla_met' + customer_suffix, 0)
                customer_sla_count_list[0][1] = cache.get('month_1_resolution_sla_met' + customer_suffix, 0)
                customer_sla_count_list[0][2] = cache.get('month_2_resolution_sla_met' + customer_suffix, 0)
                customer_sla_count_list[0][3] = cache.get('month_3_resolution_sla_met' + customer_suffix, 0)
                customer_sla_count_list[0][4] = cache.get('month_4_resolution_sla_met' + customer_suffix, 0)
                customer_sla_count_list[0][5] = cache.get('month_5_resolution_sla_met' + customer_suffix, 0)
                customer_sla_count_list[1][0] = cache.get('month_0_resolution_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[1][1] = cache.get('month_1_resolution_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[1][2] = cache.get('month_2_resolution_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[1][3] = cache.get('month_3_resolution_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[1][4] = cache.get('month_4_resolution_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[1][5] = cache.get('month_5_resolution_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[2][0] = cache.get('month_0_response_sla_met' + customer_suffix, 0)
                customer_sla_count_list[2][1] = cache.get('month_1_response_sla_met' + customer_suffix, 0)
                customer_sla_count_list[2][2] = cache.get('month_2_response_sla_met' + customer_suffix, 0)
                customer_sla_count_list[2][3] = cache.get('month_3_response_sla_met' + customer_suffix, 0)
                customer_sla_count_list[2][4] = cache.get('month_4_response_sla_met' + customer_suffix, 0)
                customer_sla_count_list[2][5] = cache.get('month_5_response_sla_met' + customer_suffix, 0)
                customer_sla_count_list[3][0] = cache.get('month_0_response_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[3][1] = cache.get('month_1_response_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[3][2] = cache.get('month_2_response_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[3][3] = cache.get('month_3_response_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[3][4] = cache.get('month_4_response_sla_failed' + customer_suffix, 0)
                customer_sla_count_list[3][5] = cache.get('month_5_response_sla_failed' + customer_suffix, 0)
                customer_sla_data_map[customer.pk] = customer_sla_count_list
            context['customer_data_map'] = customer_data_map
            context['customer_sla_data_map'] = customer_sla_data_map
            context['queue_sla_data_map'] = {}
            customer_group_data_map = {}
            customer_group_sla_data_map = {}
            customer_group_list = CustomerGroup.objects.filter(tenant = app_user.tenant, is_active = True)
            for branch in default_branch_list:
                for customergroup in customer_group_list:
                    customer_group_suffix = suffix + '_' + str(branch.vendor.pk) + '_' + str(branch.pk) + '_cgb_' + str(customergroup.pk)
                    customer_group_status_count_list = []
                    customer_group_asset_count_list = []
                    customer_group_sla_count_list = [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]]
                    for status in status_list:
                        customer_group_status_call_list = get_call_list(open_calls, status, None, branch, None, None, customergroup)
                        customer_group_status_count_list.append(customer_group_status_call_list.count())
                    for asset_status in asset_status_list:
                        customer_group_asset_list = get_asset_list(final_assets, asset_status, None, branch, None, customergroup)
                        customer_group_asset_count_list.append(customer_group_asset_list.count())                        
                    branch_customer_group_id =  str(customergroup.pk) + '_' + str(branch.pk)  
                    customer_group_data_map[branch_customer_group_id] = [customer_group_status_count_list, customer_group_asset_count_list]
                    customer_group_sla_count_list[0][0] = cache.get('month_0_resolution_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[0][1] = cache.get('month_1_resolution_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[0][2] = cache.get('month_2_resolution_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[0][3] = cache.get('month_3_resolution_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[0][4] = cache.get('month_4_resolution_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[0][5] = cache.get('month_5_resolution_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[1][0] = cache.get('month_0_resolution_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[1][1] = cache.get('month_1_resolution_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[1][2] = cache.get('month_2_resolution_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[1][3] = cache.get('month_3_resolution_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[1][4] = cache.get('month_4_resolution_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[1][5] = cache.get('month_5_resolution_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[2][0] = cache.get('month_0_response_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[2][1] = cache.get('month_1_response_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[2][2] = cache.get('month_2_response_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[2][3] = cache.get('month_3_response_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[2][4] = cache.get('month_4_response_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[2][5] = cache.get('month_5_response_sla_met' + customer_group_suffix, 0)
                    customer_group_sla_count_list[3][0] = cache.get('month_0_response_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[3][1] = cache.get('month_1_response_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[3][2] = cache.get('month_2_response_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[3][3] = cache.get('month_3_response_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[3][4] = cache.get('month_4_response_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_count_list[3][5] = cache.get('month_5_response_sla_failed' + customer_group_suffix, 0)
                    customer_group_sla_data_map[branch_customer_group_id] = customer_group_sla_count_list
            context['customer_group_data_map'] = customer_group_data_map
            context['customer_group_sla_data_map'] = customer_group_sla_data_map
            #cgcode_start
            customer_group_only_data_map = {}
            customer_group_only_sla_data_map = {}            
            for customergroup in customer_group_list:
                customer_group_suffix = suffix + '_' + str(customergroup.vendor.pk) + '_cg_' + str(customergroup.pk)
                customer_group_only_status_count_list = []
                customer_group_only_asset_count_list = []
                customer_group_only_sla_count_list = [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]]
                for status in status_list:
                    customer_group_only_status_call_list = get_call_list(open_calls, status, None, None, None, None, customergroup)
                    customer_group_only_status_count_list.append(customer_group_only_status_call_list.count())
                for asset_status in asset_status_list:
                    customer_group_only_asset_list = get_asset_list(final_assets, asset_status, None, None, None, customergroup)
                    customer_group_only_asset_count_list.append(customer_group_only_asset_list.count())                        
                customer_group_only_id =  'cg' + str(customergroup.pk)
                customer_group_only_data_map[customer_group_only_id] = [customer_group_only_status_count_list, customer_group_only_asset_count_list]
                customer_group_only_sla_count_list[0][0] = cache.get('month_0_resolution_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[0][1] = cache.get('month_1_resolution_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[0][2] = cache.get('month_2_resolution_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[0][3] = cache.get('month_3_resolution_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[0][4] = cache.get('month_4_resolution_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[0][5] = cache.get('month_5_resolution_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[1][0] = cache.get('month_0_resolution_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[1][1] = cache.get('month_1_resolution_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[1][2] = cache.get('month_2_resolution_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[1][3] = cache.get('month_3_resolution_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[1][4] = cache.get('month_4_resolution_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[1][5] = cache.get('month_5_resolution_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[2][0] = cache.get('month_0_response_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[2][1] = cache.get('month_1_response_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[2][2] = cache.get('month_2_response_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[2][3] = cache.get('month_3_response_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[2][4] = cache.get('month_4_response_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[2][5] = cache.get('month_5_response_sla_met' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[3][0] = cache.get('month_0_response_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[3][1] = cache.get('month_1_response_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[3][2] = cache.get('month_2_response_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[3][3] = cache.get('month_3_response_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[3][4] = cache.get('month_4_response_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_count_list[3][5] = cache.get('month_5_response_sla_failed' + customer_group_suffix, 0)
                customer_group_only_sla_data_map[customer_group_only_id] = customer_group_only_sla_count_list
            context['customer_group_only_data_map'] = customer_group_only_data_map
            context['customer_group_only_sla_data_map'] = customer_group_only_sla_data_map            
            #cgcode_end
        else:
            queue_sla_data_map = {}
            queue_data_map = {}
            default_queue_list = app_user.access_queues.filter(tenant = app_user.tenant, is_active = True).order_by('name')
            has_multiple_queues = True
            if len(user_queues) == 0:
                default_queue_list = Queue.objects.filter(tenant = app_user.tenant, is_active = True).order_by('name')
            if len(user_queues) == 1:
                has_multiple_queues = False
            for queue in default_queue_list:
                queue_suffix = suffix + '_' + str(queue.pk)
                queue_status_count_list = []
                queue_sla_count_list = [[0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]]
                for status in status_list:
                    queue_status_call_list = get_call_list(open_calls, status, None, None, None, queue)
                    queue_status_count_list.append(queue_status_call_list.count())
                queue_data_map[queue.pk] = queue_status_count_list
                queue_sla_count_list[0][0] = cache.get('month_0_resolution_sla_met' + queue_suffix, 0)
                queue_sla_count_list[0][1] = cache.get('month_1_resolution_sla_met' + queue_suffix, 0)
                queue_sla_count_list[0][2] = cache.get('month_2_resolution_sla_met' + queue_suffix, 0)
                queue_sla_count_list[0][3] = cache.get('month_3_resolution_sla_met' + queue_suffix, 0)
                queue_sla_count_list[0][4] = cache.get('month_4_resolution_sla_met' + queue_suffix, 0)
                queue_sla_count_list[0][5] = cache.get('month_5_resolution_sla_met' + queue_suffix, 0)
                queue_sla_count_list[1][0] = cache.get('month_0_resolution_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[1][1] = cache.get('month_1_resolution_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[1][2] = cache.get('month_2_resolution_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[1][3] = cache.get('month_3_resolution_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[1][4] = cache.get('month_4_resolution_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[1][5] = cache.get('month_5_resolution_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[2][0] = cache.get('month_0_response_sla_met' + queue_suffix, 0)
                queue_sla_count_list[2][1] = cache.get('month_1_response_sla_met' + queue_suffix, 0)
                queue_sla_count_list[2][2] = cache.get('month_2_response_sla_met' + queue_suffix, 0)
                queue_sla_count_list[2][3] = cache.get('month_3_response_sla_met' + queue_suffix, 0)
                queue_sla_count_list[2][4] = cache.get('month_4_response_sla_met' + queue_suffix, 0)
                queue_sla_count_list[2][5] = cache.get('month_5_response_sla_met' + queue_suffix, 0)
                queue_sla_count_list[3][0] = cache.get('month_0_response_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[3][1] = cache.get('month_1_response_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[3][2] = cache.get('month_2_response_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[3][3] = cache.get('month_3_response_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[3][4] = cache.get('month_4_response_sla_failed' + queue_suffix, 0)
                queue_sla_count_list[3][5] = cache.get('month_5_response_sla_failed' + queue_suffix, 0)
                queue_sla_data_map[queue.pk] = queue_sla_count_list
            context['default_queue_name_list'] = default_queue_list    
            context['queue_data_map'] = queue_data_map
            context['queue_sla_data_map'] = queue_sla_data_map
            context['branch_sla_data_map'] = {}
            context['customer_sla_data_map'] = {}
            context['has_multiple_queues'] = has_multiple_queues
            context['customer_group_data_map'] = {}
            context['customer_group_sla_data_map'] = {}
            context['customer_group_only_sla_data_map'] = {}
        #print ('branch_data_map:', branch_data_map)
        #print('customer_data_map: ', customer_data_map)
        return context


def get_asset_list(orig_list, status, vendor = None, branch = None, customer = None, customergroup = None):
    ret_val = orig_list.filter(status = status)
    if vendor:
        ret_val = ret_val.filter(customer__branch__vendor = vendor)
    if branch:
        ret_val = ret_val.filter(customer__branch = branch)
    if customer:
        ret_val = ret_val.filter(customer = customer)
    if customergroup:
        ret_val = ret_val.filter(customer__customer_group = customergroup)
    # if queue:
    #     ret_val = ret_val.filter(queue = queue)
    return ret_val

def get_call_list(orig_list, status, vendor = None, branch = None, customer = None, queue = None, customergroup = None):
    ret_val = orig_list.filter(status = status)
    if vendor:
        ret_val = ret_val.filter(vendor = vendor)
    if branch:
        ret_val = ret_val.filter(branch = branch)
    if customer:
        ret_val = ret_val.filter(customer = customer)
    if customergroup:
        ret_val = ret_val.filter(customer__customer_group = customergroup)
    if queue:
        ret_val = ret_val.filter(queue = queue)
    return ret_val


class GetCallData(AdminTemplateView):
    template_name = 'get_call_data.html'

    def get_context_data(self, **kwargs):
        context = super(GetCallData,self).get_context_data(**kwargs)
        app_user = HCMSUser.objects.get(pk = self.request.user.pk)
        sla_type = self.kwargs['sla_type']
        sla_type_str = 'resolution'
        if sla_type == '2':
            sla_type_str = 'response'
        sla_status = self.kwargs['sla_status']
        sla_status_str = 'met'
        if sla_status == '1':
            sla_status_str = 'failed'
        month_id = self.kwargs['month_id']
        key = 'month_' + month_id + '_' + sla_type_str + '_sla_' + sla_status_str + '_details_' + str(app_user.tenant.pk)
        branch_id = self.kwargs['branch_id']
        customer_id = self.kwargs['customer_id']
        queue_id = self.kwargs['queue_id']
        customer_group_id = self.kwargs['customer_group_id']
        if queue_id and queue_id !='0':
            queue = Queue.objects.get(pk = queue_id)
            key = key + '_' + str(queue.pk) 
        elif customer_group_id and customer_group_id != '0' and branch_id and branch_id != '0':
            branch = Branch.objects.get(pk = branch_id)
            key = key + '_' + str(branch.vendor.pk) + '_'+ str(branch.pk) + '_cgb_' + customer_group_id
        elif customer_group_id and customer_group_id != '0' and branch_id and branch_id == '0':
            customergroup = CustomerGroup.objects.get(pk = customer_group_id)
            key = key + '_' + str(customergroup.vendor.pk) + '_cg_' + customer_group_id
        elif customer_id and customer_id != '0':
            customer = Customer.objects.get(pk = customer_id)
            key = key + '_' + str(customer.branch.vendor.pk) + '_'+ str(customer.branch.pk) + '_' + customer_id
        elif branch_id and branch_id != '0':
            branch = Branch.objects.get(pk = branch_id)
            key = key + '_' + str(branch.vendor.pk) + '_' + branch_id
        else:
            vendor_id = self.kwargs['vendor_id']
            if vendor_id and vendor_id != '0':
                key = key + '_' + vendor_id
        user_vendors = self.request.session['user_vendor_list']
        call_list = cache.get(key)
        call_list = call_list.filter(vendor__id__in = user_vendors)
        context['call_list'] = call_list
        context['hide_sidebar'] = True
        return context
    
    
@class_view_decorator(login_required)
class ListCallTicketDetails(AdminFormView):
    form_class = CallReportForm
    template_name = 'call_records_list.html'
    redirecturl = 'administrations:list_call_tickets'

    def get_context_data(self, **kwargs):
        context = super(ListCallTicketDetails, self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        engineer_obj = Engineer.objects.filter(pk = admin_user.pk).first()
        is_engineer = False
        if engineer_obj:
            is_engineer = True
        context['is_engineer'] = is_engineer 
        config_map = self.request.config_map
        status_details = CallStatus.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        queue_list = Queue.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        customer_details = Customer.objects.filter(branch__tenant = admin_user.tenant).order_by('name')
        customer_group_list = CustomerGroup.objects.filter(tenant = admin_user.tenant).order_by('name')
        customer_group_choices = []
        customer_group_choices.append([-1, 'All'])
        for customer_group in customer_group_list:
            customer_group_choices.append([customer_group.id, customer_group.name])
        reason_code_details = ReasonCode.objects.filter(call_status__tenant = admin_user.tenant, is_active = True).order_by('rank')
        status_reasoncode_map = {}
        status_reasoncode_map[-1] = list(reason_code_details)
        for statusobj in status_details:
            status_reasoncode_list = ReasonCode.objects.filter(call_status = statusobj, is_active = True).order_by('rank')
            status_reasoncode_map[statusobj.id] = list(status_reasoncode_list)
        context['status_reasoncode_map'] = status_reasoncode_map
        vendor_choices = []
        vendor_details = None
        if len(self.request.session['user_vendors']) == 0:
            vendor_details = list(admin_user.tenant.applicable_vendors.filter(is_active = True).order_by('name'))
        else:
            vendor_details = self.request.session['user_vendors']
        have_multiple_vendors = False
        if len(vendor_details) > 1:
            vendor_choices.append([-1, 'All'])
            have_multiple_vendors = True
        vendor_id_list = []
        if len(vendor_details) > 0:
            for vendor in vendor_details:
                vendor_id_list.append(vendor.pk)
        context['have_multiple_vendors'] = have_multiple_vendors
        for vendor in vendor_details:
            vendor_choices.append([vendor.id, vendor.name])
        branch_id_list = []
        if len(self.request.session['user_branches']) > 0:
            for obj in self.request.session['user_branches']:
                branch_id_list.append(obj.pk)
        branch_choices = []
        branch_details = None
        if len(self.request.session['user_branches']) == 0:
            branch_details = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
            if len(vendor_id_list) > 0:
                branch_details = branch_details.filter(vendor__id__in = vendor_id_list)
        else:
            if len(vendor_id_list) > 0:
                branch_details =  Branch.objects.filter(Q(vendor__id__in = vendor_id_list)|Q(pk__in = branch_id_list), tenant = admin_user.tenant, is_active = True).order_by('name')
            else:  
                branch_details = self.request.session['user_branches']
        have_multiple_branches = False
        if len(branch_details) > 1:
            branch_choices.append([-1, 'All'])
            have_multiple_branches = True
        context['have_multiple_branches'] = have_multiple_branches
        for branch in branch_details:
            branch_choices.append([branch.id, branch.get_branch_vendor_value()])
        status_choices = []
        status_choices.append([-1, 'All'])
        for status in status_details:
            status_choices.append([status.id, status.name])
        reason_code_choices = []
        reason_code_choices.append([-1, 'All'])
        for reason_code in reason_code_details:
            reason_code_choices.append([reason_code.id, reason_code.name])
        customer_choices = []
        customer_id_list = []
        customer_details = None
        if len(self.request.session['user_customers']) > 0:
            customer_details = self.request.session['user_customers']
        have_multiple_customers = False
        if customer_details and len(customer_details) > 1:
            customer_choices.append([-1,'All' ])
            have_multiple_customers = True
        context['have_multiple_customers'] = have_multiple_customers
        if customer_details:
            for customer in customer_details:
                customer_choices.append([customer.id, customer.name])
        if not self.request.session['customer_admin']:
            customer_choices = []
            customer_choices.append([-1, 'All'])
        if self.request.session['customer_admin']:
            branch_choices = []
            branch_choices.append([-1, 'All'])   
        if len(self.request.session['user_queues']) == 0:
            queue_list = list(queue_list)
        else:
            queue_list = self.request.session['user_queues']
        queue_choices = [] 
        have_multiple_queues = False
        if len(queue_list) > 1:
            queue_choices.append([-1, 'All'])
            have_multiple_queues = True
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'True':
            queue_choices = []
            queue_choices.append([-1, 'All'])
        context['have_multiple_queues'] = have_multiple_queues
        for queue in queue_list:
            queue_choices.append([queue.id, queue.name])
        context['form'] = self.form_class(vendor_choices, branch_choices, status_choices, reason_code_choices, customer_choices, queue_choices, customer_group_choices)
        filter_map = cache.get('call_ticket_filter_map_' + str(admin_user.pk))
        if filter_map:
            selected_vendor = filter_map['selected_vendor']
            selected_branch = filter_map['selected_branch']
            selected_customer = filter_map['selected_customer']
            selected_status = filter_map['selected_status']
            selected_reason_code = filter_map['selected_reason_code']
            selected_queue = filter_map['selected_queue']
            selected_customer_groups = filter_map['selected_customer_groups']
            start_date = filter_map['start_date']
            end_date = filter_map['end_date']
            daterangeval = filter_map['daterangeval']
        else:
            if len(vendor_details) > 1:
                selected_vendor = '-1'
            else:
                selected_vendor = vendor_details[0].pk
            if len(branch_details) > 1:
                selected_branch = '-1'
            else:
                if self.request.session['customer_admin']:
                    selected_branch = '-1'
                else:    
                    selected_branch = branch_details[0].pk
            if self.request.session['customer_admin']:      
                if len(customer_details) > 1:
                    selected_customer = '-1'
                else:
                    selected_customer = customer_details[0].pk
            else:
                selected_customer = '-1'
            selected_status = '-1'
            selected_reason_code = '-1'
            selected_queue = '-1'
            selected_customer_groups = '-1'
            time_offset = pytz.timezone(self.request.session['DEFAULT_TIME_ZONE'])
            start_date = timezone.now() + timedelta(-29)
            to_date = timezone.now()
            from_date = "{:%Y%m%d}".format(start_date)
            to_date = "{:%Y%m%d}".format(to_date)
            fdate = datetime.strptime(from_date,"%Y%m%d").date()
            tdate = datetime.strptime(to_date,"%Y%m%d").date()
            fdatestr = datetime(fdate.year, fdate.month, fdate.day)
            tdatestr = datetime(tdate.year, tdate.month, tdate.day)
            fdtstr = fdatestr.strftime("%Y-%m-%d")
            tdtstr = tdatestr.strftime("%Y-%m-%d")
            daterangeval = fdtstr + str(" - ") + tdtstr
            start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
            end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
            end_date = end_date + relativedelta(days = 1)
            filter_map = {}
            filter_map['selected_vendor'] = selected_vendor
            filter_map['selected_branch'] = selected_branch
            filter_map['selected_status'] = selected_status
            filter_map['selected_customer'] = selected_customer
            filter_map['selected_reason_code'] = selected_reason_code
            filter_map['selected_queue'] = selected_queue
            filter_map['selected_customer_groups'] = selected_customer_groups
            filter_map['start_date'] = start_date
            filter_map['end_date'] = end_date
            filter_map['daterangeval'] = daterangeval
        cache.set('call_ticket_filter_map_' + str(admin_user.pk), filter_map, 180)
        context['form'].fields['vendor'].initial = selected_vendor
        context['form'].fields['branch'].initial = selected_branch
        context['form'].fields['access_customers'].initial = selected_customer
        context['form'].fields['status'].initial = selected_status
        context['form'].fields['reason_code'].initial = selected_reason_code
        context['form'].fields['daterange'].initial = daterangeval
        context['form'].fields['queue'].initial = selected_queue
        context['form'].fields['access_customer_groups'].initial = selected_customer_groups
        boot_details = get_call_ticket_list_for_customer(selected_vendor, selected_branch, selected_status, selected_customer, admin_user.tenant, selected_reason_code, start_date, end_date, self.request.session['user_vendor_list'], self.request.session['user_branch_list'], self.request.session['user_customers_list'], selected_queue, self.request.session['user_queue_list'], selected_customer_groups, self.request.session['user_customer_group_list'])
        context['boot_details'] = boot_details[0]
        context['is_post'] = True
        context['daterangeval'] = daterangeval
        vendor_list = self.request.session['vendors_with_create_call_list']
        create_ticket = False
        if len(vendor_list) > 0:
            create_ticket = True
        context['create_ticket'] = create_ticket 
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'False':
            self.template_name = 'call_records_list_cipla.html'
        return context
    
    def get(self, request, *args, **kwargs):
        if not can_access_itemname('CALLDETAIL_ITEM', request.session['tenant'], '', request.session['admin_roles'], 1):
            logger.error('Invalid request by User [' + request.user.username + ']: Attempting to access list call details page')
            return HttpResponseRedirect(reverse('request_error'))
        config_map = request.config_map
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'False':
            self.template_name = 'call_records_list_cipla.html'
        request.session['active_tab'] = '4'
        request.session['call_ticket_breadcrumb_source'] = '1'
        return super(ListCallTicketDetails, self).get(request, args, kwargs)
    
    def get_success_url(self):
        return reverse_lazy(self.redirecturl)
   
    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        time_offset = pytz.timezone(request.session['DEFAULT_TIME_ZONE'])
        selected_vendor = request.POST.get('vendor')
        selected_branch = request.POST.get('branch')
        selected_customer = request.POST.get('access_customers')
        selected_status = request.POST.get('status')
        selected_reason_code = request.POST.get('reason_code')
        selected_queue = request.POST.get('queue')
        selected_customer_groups = request.POST.get('access_customer_groups')
        daterangeval = request.POST.get('daterange')
        split_set = daterangeval.split(' - ')
        from_date = split_set[0]
        to_date = split_set[1]
        fdate = datetime.strptime(from_date,"%Y-%m-%d").date()
        tdate = datetime.strptime(to_date,"%Y-%m-%d").date()
        start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
        end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
        end_date = end_date + relativedelta(days = 1)
        filter_map = {}
        filter_map['selected_vendor'] = selected_vendor
        filter_map['selected_branch'] = selected_branch
        filter_map['selected_status'] = selected_status
        filter_map['selected_customer'] = selected_customer
        filter_map['selected_reason_code'] = selected_reason_code
        filter_map['selected_queue'] = selected_queue
        filter_map['selected_customer_groups'] = selected_customer_groups
        filter_map['start_date'] = start_date
        filter_map['end_date'] = end_date
        filter_map['daterangeval'] = daterangeval
        cache.set('call_ticket_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(ListCallTicketDetails, self).post(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayCallTicketDetails(AdminTemplateView):
    template_name = 'display_call_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallTicketDetails, self).get_context_data(**kwargs)
        context['active_tab'] = self.request.session.get('active_tab', '0')
        callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callobj
        status_reasoncode_map = {}
        status_reasoncode_map[0] = []
        status_list = CallStatus.objects.filter(is_active = True).order_by('rank')
        hide_reason_code_id_list =  []
        hide_reason_code_list = HideCallReasonCodeForVendor.objects.filter(vendor = callobj.vendor, tenant = callobj.tenant, app_type = 1)
        for obj in hide_reason_code_list:
            hide_reason_code_id_list.append(obj.reasoncode.pk)
        for statusobj in status_list:
            status_reasoncode_list = ReasonCode.objects.filter(call_status = statusobj, is_active = True).exclude(id__in = hide_reason_code_id_list).order_by('rank')
            status_reasoncode_map[statusobj.id] = list(status_reasoncode_list)
        context['status_reasoncode_map'] = status_reasoncode_map
        call_machine_list = TicketMachineDetails.objects.filter(ticket = callobj)
        machine_list = Machine.objects.filter(vendor = callobj.vendor)
        call_line_items_list = TicketLineItem.objects.filter(ticket = callobj).order_by('-line_id')
        call_status_track_list = TicketStatusTrack.objects.filter(ticket = callobj).order_by('-status_change_time')
        call_notes_list = TicketNotes.objects.filter(ticket = callobj).order_by('-notes_entered_time')
        call_document_list = TicketDocument.objects.filter(ticket = callobj).order_by('-upload_time')
        call_customer_feedback_list = TicketCustomerFeedback.objects.filter(ticket = callobj)
        call_engineer_feedback_list = TicketClosureNotes.objects.filter(ticket = callobj)
        call_feedback_list = TicketCallFeedback.objects.filter(ticket = callobj)
        call_changes_audit_list = TicketChangesAudit.objects.filter(ticket = callobj).order_by('-updated_time')
        call_machine_obj= call_machine_list.first()
        machine_obj = None
        if call_machine_obj:
            machine_obj = Machine.objects.filter(serial_number = call_machine_obj.serial_number).first()
        context['machine_obj'] = machine_obj
        context['call_machine_list'] = call_machine_list
        context['call_machine_obj']= call_machine_list.first()
        context['call_line_items_list'] = call_line_items_list
        context['call_status_track_list'] = call_status_track_list
        context['call_notes_list'] = call_notes_list
        context['call_document_list'] = call_document_list
        context['call_customer_feedback_list'] = call_customer_feedback_list
        context['call_customer_feedback_obj'] = call_customer_feedback_list.last()
        context['call_engineer_feedback_list'] = call_engineer_feedback_list
        context['call_engineer_feedback_obj'] = call_engineer_feedback_list.last()
        context['call_feedback_obj'] = call_feedback_list.last()
        context['call_changes_audit_list'] = call_changes_audit_list
        call_status_assign_engineer_track_list = AssignedEngineerTrack.objects.filter(ticket = callobj).order_by('-modified_time')
        #context['created_time'] = created_time
        context['call_status_assign_engineer_track_list'] = call_status_assign_engineer_track_list
        reasoncode_fields_map = {}
        reasoncode_list = ReasonCode.objects.filter(call_status__tenant = callobj.tenant, is_active = True).order_by('rank')
        for reasoncode in reasoncode_list:
            field_list = FieldReasonCodeMap.objects.filter(tenant = callobj.tenant, reason_code = reasoncode)
            reasoncode_fields_map[reasoncode.id] = list(field_list)
        context['reasoncode_fields_map'] = reasoncode_fields_map
        reason_code_protected_fields = []
        field_reasoncode_list = FieldReasonCodeMap.objects.filter(tenant = callobj.tenant)
        for field_reasoncode in field_reasoncode_list:
            access_field = field_reasoncode.access_field
            if not access_field.field_id in reason_code_protected_fields:
                reason_code_protected_fields.append(access_field.field_id)
        context['reason_code_protected_fields'] = reason_code_protected_fields
        if callobj.customer:
            severity_level_label = callobj.customer.severity_name
            tier_label = callobj.customer.tier_name
            department_label = callobj.customer.department_name
            location_type_label = callobj.customer.location_type_name
        else:
            tenantvendormappingobj = TenantVendorMapping.objects.filter(tenant = callobj.tenant, vendor = callobj.vendor).first()
            severity_level_label = tenantvendormappingobj.severity_name
            tier_label = tenantvendormappingobj.tier_name
            department_label = tenantvendormappingobj.department_name
            location_type_label = tenantvendormappingobj.location_type_name
        context['severity_level_label'] = severity_level_label    
        context['tier_label'] = tier_label    
        context['department_label'] = department_label 
        context['location_type_label'] = location_type_label
        return context

    def get(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        callobj = CallTicket.objects.get(pk = kwargs['pk'])
        call_machine_list = TicketMachineDetails.objects.filter(ticket = callobj)
        call_line_items_list = TicketLineItem.objects.filter(ticket = callobj).order_by('-line_id')
        call_status_track_list = TicketStatusTrack.objects.filter(ticket = callobj).order_by('-status_change_time')
        call_notes_list = TicketNotes.objects.filter(ticket = callobj).order_by('-notes_entered_time')
        call_document_list = TicketDocument.objects.filter(ticket = callobj).order_by('-upload_time')
        call_customer_feedback_list = TicketCustomerFeedback.objects.filter(ticket = callobj)
        call_engineer_feedback_list = TicketClosureNotes.objects.filter(ticket = callobj)
        call_changes_audit_list = TicketChangesAudit.objects.filter(ticket = callobj).order_by('-updated_time')
        #if admin_user.call_details:
        #    if customer_details.pk != admin_user.customer.id:
        #        return HttpResponseRedirect(reverse('common:common_requesterror'))
        #else:
        #    return HttpResponseRedirect(reverse('common:common_requesterror'))
        self.callobj = callobj
        self.call_machine_list = call_machine_list
        self.call_machine_obj = call_machine_list.first()
        self.call_line_items_list = call_line_items_list
        self.call_status_track_list = call_status_track_list
        self.call_notes_list = call_notes_list
        self.call_document_list = call_document_list
        self.call_changes_audit_list = call_changes_audit_list
        self.call_customer_feedback_list = call_customer_feedback_list
        self.call_customer_feedback_obj = call_customer_feedback_list.first()
        self.call_engineer_feedback_list = call_engineer_feedback_list
        self.call_engineer_feedback_obj = call_engineer_feedback_list.first()
        return super(DisplayCallTicketDetails, self).get(request, args, kwargs) 

@class_view_decorator(login_required)
class ListMachines(AdminListView):
    model = Machine
    template_name = 'list_machines.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        if self.request.session['customer_admin']: 
            customer_id_list = []
            customer_details = self.request.session['user_customers']
            for customer in customer_details:
                customer_id_list.append(customer.id)
                queryset = Machine.objects.filter(customer__pk__in = customer_id_list)
        config_map = self.request.config_map
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'False':
            queryset = Machine.objects.filter(branch__tenant = admin_user.tenant)
        else:
            queryset = Machine.objects.filter(customer__branch__tenant = admin_user.tenant)
        return queryset
    def get(self, request, *args, **kwargs):
        return super(ListMachines, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayMachineDetails(AdminTemplateView):
    template_name = 'display_machine_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayMachineDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        machine_details = Machine.objects.get(pk = kwargs['pk'])
        self.machine_details = machine_details
        return super(DisplayMachineDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateMachine(AdminCreateView):
    model = Machine
    form_class = CreateMachineForm
    template_name = 'create_machine.html'
    success_message = 'New Machine created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateMachine,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        customer_details = Customer.objects.filter(branch__tenant = adminobj.tenant).order_by('name')
        machine_type_details = MachineType.objects.filter(tenant = adminobj.tenant, is_active = True)
        machine_make_details = MachineMake.objects.filter(tenant = adminobj.tenant, is_active = True)
        model_details = MachineModel.objects.filter(machine_type__tenant = adminobj.tenant, is_active = True).order_by('name')
        operating_system = OperatingSystem.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        ram_type_list = RAM.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        hard_disk_list  = HardiskType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        warranty_type = WarrantyType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        branch_list = Branch.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        branch_choices = []
        branch_choices.append([-1, '--------------'])
        for branch in branch_list:
            branch_choices.append([branch.id, branch.get_branch_vendor_value()])
        context['form'].fields['branch'].choices =  branch_choices
        if self.request.session['customer_admin']:
            customer_details = self.request.session['user_customers']
        final_model_list = []
        final_type_list = []
        final_make_list = []
        machine_type_model_make_map = {}
        machine_make_model_type_map = {}
        machine_type_make_model_map = {}
        final_type_list.append(['0', '---------'])
        final_make_list.append(['0', '---------'])
        final_model_list.append(['0', '---------'])
        type_model_list = []
        machine_type_model_make_map[0] = [list(machine_make_details), list(model_details)]
        machine_make_model_type_map[0] = [list(machine_type_details), list(model_details)]
        machine_type_make_model_map[0] = list(model_details)
        for model in model_details:
            final_model_list.append([model.pk, model.name])
        for make in machine_make_details:
            final_make_list.append([make.pk, make.name])
            make_model_details = model_details.filter(machine_make = make)
            type_list = []
            for model in make_model_details:
                type_list.append(model.machine_type)
            type_list_set = set(type_list)
            machine_make_model_type_map[make.pk] = [type_list_set, list(make_model_details)]
        for machinetype in machine_type_details:
            final_type_list.append([machinetype.pk, machinetype.name])
            type_model_details = model_details.filter(machine_type = machinetype)
            make_list = []
            for model in type_model_details:
                make_list.append(model.machine_make)
            make_list_set = set(make_list)
            for make in make_list_set:
                type_make_val = str(machinetype.pk) + '_' + str(make.pk)
                make_model_details = model_details.filter(machine_make = make, machine_type = machinetype)
                machine_type_make_model_map[type_make_val] = list(make_model_details)
            machine_type_model_make_map[machinetype.pk] = [make_list_set, list(type_model_details)]
        customer_list = []
        customer_list.append(['0','--------' ])
        for customer in customer_details:
            if customer.is_customer_complete_one(): 
                concatVal = customer.name + ' - ' + customer.branch.name + ' - ' + customer.address
                customer_list.append([customer.id, concatVal])
        config_map = self.request.config_map
        context['form'].fields['customer'].choices  = customer_list
        context['form'].fields['model'].choices  = final_model_list
        context['form'].fields['machine_type'].choices  = final_type_list
        context['form'].fields['machine_make'].choices  = final_make_list
        context['form'].fields['operating_system'].queryset =  operating_system
        context['form'].fields['ram_type'].queryset =  ram_type_list 
        context['form'].fields['hard_disk_type'].queryset =  hard_disk_list 
        context['form'].fields['warranty_type'].queryset =  warranty_type
        context['machine_type_model_make_map'] = machine_type_model_make_map
        context['machine_make_model_type_map'] = machine_make_model_type_map
        context['machine_type_make_model_map'] = machine_type_make_model_map
        return context

    def get_form_kwargs(self):
        kw = super(CreateMachine, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        return super(CreateMachine,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateMachine, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Asset created successfully'
        return reverse('administrations:list_machines')

@class_view_decorator(login_required)
class UpdateMachineDetails(AdminUpdateView):
    model = Machine
    form_class = UpdateMachineDetailForm
    template_name = 'update_machine_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateMachineDetails,self).get_context_data(**kwargs)
        machineObj = Machine.objects.get(pk = self.kwargs['pk'])
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        customer_details = Customer.objects.filter(branch__tenant = adminobj.tenant).order_by('name')
        machine_type_details = MachineType.objects.filter(tenant = adminobj.tenant, is_active = True)
        machine_make_details = MachineMake.objects.filter(tenant = adminobj.tenant, is_active = True)
        model_details = MachineModel.objects.filter(machine_type__tenant = adminobj.tenant, is_active = True).order_by('name')
        operating_system = OperatingSystem.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        ram_type_list = RAM.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        hard_disk_type_list = HardiskType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        warranty_type = WarrantyType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        ticket_machine_details = TicketMachineDetails.objects.filter(serial_number = machineObj.serial_number)
        branch_list = Branch.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        branch_choices = []
        branch_choices.append([-1, '--------------'])
        for branch in branch_list:
            branch_choices.append([branch.id, branch.get_branch_vendor_value()])
        context['form'].fields['branch'].choices =  branch_choices
        ticket_machine_id_list = []
        for ticketmachine in ticket_machine_details:
            ticket_machine_id_list.append(ticketmachine.ticket.id)
        callObj = CallTicket.objects.filter(pk__in = ticket_machine_id_list)
        context['callObj'] = callObj
        if self.request.session['customer_admin']:
            customer_details = self.request.session['user_customers']
        customer_list = []
        final_model_list = []
        final_type_list = []
        final_make_list = []
        machine_type_model_make_map = {}
        machine_make_model_type_map = {}
        machine_type_make_model_map = {}
        customer_list.append(['0', '---------'])
        final_type_list.append(['0', '---------'])
        final_make_list.append(['0', '---------'])
        final_model_list.append(['0', '---------'])
        type_model_list = []
        machine_type_model_make_map[0] = [list(machine_make_details), list(model_details)]
        machine_make_model_type_map[0] = [list(machine_type_details), list(model_details)]
        machine_type_make_model_map[0] = list(model_details)
        for model in model_details:
            final_model_list.append([model.pk, model.name])
        for make in machine_make_details:
            final_make_list.append([make.pk, make.name])
            make_model_details = model_details.filter(machine_make = make)
            type_list = []
            for model in make_model_details:
                type_list.append(model.machine_type)
            type_list_set = set(type_list)
            machine_make_model_type_map[make.pk] = [type_list_set, list(make_model_details)]
        for machinetype in machine_type_details:
            final_type_list.append([machinetype.pk, machinetype.name])
            type_model_details = model_details.filter(machine_type = machinetype)
            make_list = []
            for model in type_model_details:
                make_list.append(model.machine_make)
            make_list_set = set(make_list)
            for make in make_list_set:
                type_make_val = str(machinetype.pk) + '_' + str(make.pk)
                make_model_details = model_details.filter(machine_make = make, machine_type = machinetype)
                machine_type_make_model_map[type_make_val] = list(make_model_details)
            machine_type_model_make_map[machinetype.pk] = [make_list_set, list(type_model_details)]
        for customer in customer_details:
            if customer.is_customer_complete_one(): 
                concatVal = customer.name + ' - ' + customer.branch.name + ' - ' + customer.address
                customer_list.append([customer.id, concatVal])
        config_map = self.request.config_map
        context['form'].fields['machine_type'].initial = machineObj.model.machine_type.pk
        context['form'].fields['machine_make'].initial = machineObj.model.machine_make.pk
        context['form'].fields['customer'].choices  = customer_list
        context['form'].fields['model'].choices  = final_model_list
        context['form'].fields['machine_type'].choices  = final_type_list
        context['form'].fields['machine_make'].choices  = final_make_list
        context['form'].fields['operating_system'].queryset =  operating_system
        context['form'].fields['warranty_type'].queryset =  warranty_type
        context['machine_type_model_make_map'] = machine_type_model_make_map
        context['machine_make_model_type_map'] = machine_make_model_type_map
        context['machine_type_make_model_map'] = machine_type_make_model_map
        context['machineObj'] = machineObj
        context['ticket_machine_details'] = ticket_machine_details
        context['ticket_machine_count'] = ticket_machine_details.count()
        context['form'].fields['ram_type'].queryset =  ram_type_list
        context['form'].fields['hard_disk_type'].queryset =  hard_disk_type_list
        return context

    def get(self, request, *args, **kwargs):
        request.session['call_ticket_breadcrumb_source'] = '2'
        return super(UpdateMachineDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateMachineDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        machine_details = Machine.objects.get(pk = self.kwargs['pk'])
        kw['machine_details'] = machine_details
        return kw

    def post(self, request, *args, **kwargs):
        machineObj = Machine.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Asset details sucessfully!'
        return super(UpdateMachineDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_machines')


@class_view_decorator(login_required)
class ListCustomers(AdminListView):
    model = Customer
    template_name = 'list_customers.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Customer.objects.filter(branch__tenant = admin_user.tenant)
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListCustomers,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '0'
        return super(ListCustomers, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayCustomerDetails(AdminTemplateView):
    template_name = 'display_customer_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCustomerDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        customer_details = Customer.objects.get(pk = kwargs['pk'])
        self.customer_details = customer_details
        return super(DisplayCustomerDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class CreateCustomer(AdminCreateView):
    model = Customer
    form_class = CreateCustomerForm
    template_name = 'create_customer.html'
    #success_message = 'New Customer created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateCustomer,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        #location_details = Location.objects.filter(branch__tenant = adminobj.tenant, is_active = True).order_by('name')
        user_status_details = UserStatus.objects.filter(tenant = adminobj.tenant, is_active = True)
        #context['form'].fields['location'].queryset =  location_details
        #context['form'].fields['status'].queryset = user_status_details
        vendor_list = self.request.session['vendor_customer_create_list']
        branch_list = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor__pk__in = vendor_list)
        locationlist = Location.objects.filter(branch__in = branch_list).order_by('name')
        customergroup_list = CustomerGroup.objects.filter(tenant = adminobj.tenant, is_active = True, vendor__pk__in = vendor_list)
        vendor_choices = []
        vendor_choices.append(['0','-------'])
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                vendor_choices.append([vendorobj.id, vendorobj.name])
        context['form'].fields['vendor'].choices =  vendor_choices
        hide_vendor = False
        if len(vendor_list) == 1:
            context['form'].fields['vendor'].initial = vendor_list[0]
            branch_list = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor__pk = vendor_list[0]).order_by('name')
            hide_vendor = True
        context['hide_vendor'] = hide_vendor
        vendor_branch_map = {}
        vendor_branch_map[0] = branch_list
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                branchObj = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor = vendorobj).order_by('name')
                vendor_branch_map[vendorobj.pk] = branchObj
        branch_location_map = {}
        branch_location_map['0'] = locationlist
        if branch_list:
            for branch in branch_list:
                locationlist = Location.objects.filter(branch = branch)
                branch_location_map[branch.pk]= list(locationlist)
        vendor_customergroup_map = {}
        vendor_customergroup_map['0'] = customergroup_list
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                customergroupObj = CustomerGroup.objects.filter(tenant = adminobj.tenant, is_active = True, vendor = vendorobj).order_by('name')
                vendor_customergroup_map[vendorobj.pk] = customergroupObj
        context['vendor_customergroup_map'] = vendor_customergroup_map
        context['vendor_branch_map'] = vendor_branch_map
        context['branch_location_map'] = branch_location_map
        today = datetime.now() + timedelta(minutes = 330)
        context['form'].fields['working_time_start'].initial = today.strftime('%I:%M %p')
        context['form'].fields['working_time_end'].initial = today.strftime('%I:%M %p')
        return context

    def get_form_kwargs(self):
        kw = super(CreateCustomer, self).get_form_kwargs()
        customer_name_list = []
        customer_phone_list = []
        customer_alt_phone_list = []
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        customer_details = Customer.objects.filter(branch__tenant = admin_user.tenant)
        for customer in customer_details:
            customer_name_list.append(customer.get_name_address_value())
            customer_phone_list.append(customer.phone)
            customer_alt_phone_list.append(customer.alt_phone)
        kw['customer_name_list'] = customer_name_list
        kw['customer_phone_list'] = customer_phone_list
        kw['customer_alt_phone_list'] = customer_alt_phone_list
        return kw

    def form_valid(self, form):
        form.instance.status = CustomerStatus.objects.get(name = 'Approved')
        form.instance.phone = validate_mobile_countryCode(self.request.POST.get('phone'))
        form.instance.alt_phone = validate_mobile_countryCode(self.request.POST.get('alt_phone'))
        working_time_end = self.request.POST.get('working_time_end')
        working_time_start = self.request.POST.get('working_time_start')
        if working_time_end and working_time_start:
            working_time_end = convert_time_str_to_time_arr(working_time_end)
            hours = int(working_time_end[0]) * 60
            minutes = int(working_time_end[1])
            working_time_end_in_minutes = hours + minutes
            working_time_start = convert_time_str_to_time_arr(working_time_start)
            hours = int(working_time_start[0]) * 60
            minutes = int(working_time_start[1])
            working_time_start_in_minutes = hours + minutes
            form.instance.working_start_time = working_time_start_in_minutes
            form.instance.working_end_time = working_time_end_in_minutes
        return super(CreateCustomer,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCustomer, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Customer created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.object.pk})

@class_view_decorator(login_required)
class UpdateCustomerDetails(AdminUpdateView):
    model = Customer
    form_class = UpdateCustomerDetailForm
    template_name = 'update_customer_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCustomerDetails,self).get_context_data(**kwargs)
        context['active_tab'] = self.request.session.get('active_tab', '0')
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        #location_details = Location.objects.filter(branch__tenant = adminobj.tenant, is_active = True).order_by('name')
        customerObj = Customer.objects.get(pk = self.kwargs['pk'])
        user_status_details = UserStatus.objects.filter(tenant = adminobj.tenant, is_active = True)
        severity_level_list = SeverityLevel.objects.filter(customer = customerObj)
        tier_list = Tier.objects.filter(customer = customerObj)
        holiday_list = Holiday.objects.filter(customer = customerObj)
        sla_list = SLA.objects.filter(customer = customerObj)
        #context['form'].fields['location'].queryset =  location_details
        #context['form'].fields['status'].queryset = user_status_details
        has_severity_level = customerObj.has_severity_level()
        department = Department.objects.filter(customer = customerObj)
        location_type = LocationType.objects.filter(customer = customerObj)
        working_start_time = timedelta(minutes= customerObj.working_start_time)
        working_end_time = timedelta(minutes= customerObj.working_end_time)
        context['form'].fields['working_time_start'].initial = working_start_time
        context['form'].fields['working_time_end'].initial = working_end_time
        context['customerObj'] = customerObj
        vendor_list = self.request.session['vendor_customer_create_list']
        branch_list = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor__pk__in = vendor_list)
        locationlist = Location.objects.filter(branch__in = branch_list).order_by('name')
        customergroup_list = CustomerGroup.objects.filter(tenant = adminobj.tenant, is_active = True, vendor__pk__in = vendor_list)
        vendor_choices = []
        vendor_choices.append(['0','-------'])
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                vendor_choices.append([vendorobj.id, vendorobj.name])
        context['form'].fields['vendor'].choices =  vendor_choices       
        hide_vendor = False
        if len(vendor_list) == 1:
            context['form'].fields['vendor'].initial = vendor_list[0]
            branch_list = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor__pk = vendor_list[0]).order_by('name')
            hide_vendor = True
        context['form'].fields['vendor'].initial = customerObj.branch.vendor.pk
        context['hide_vendor'] = hide_vendor
        context['severity_level_list'] = severity_level_list
        context['tier_list'] = tier_list
        context['department'] = department
        context['location_type'] = location_type
        context['holiday_list'] = holiday_list
        context['sla_list'] = sla_list
        if customerObj.has_severity_level():
            context['form'].fields['severity_based_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA already exist with Severity Level, so you won\'t be able to uncheck this checkbox'}
        if customerObj.has_tier():
            context['form'].fields['tier_based_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA already exist with Tier, so you won\'t be able to uncheck this checkbox'}
        if customerObj.has_department():
            context['form'].fields['department_based_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA already exist with Department, so you won\'t be able to uncheck this checkbox'}
        if customerObj.has_location_type():
            context['form'].fields['location_type_based_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA already exist with Location Type, so you won\'t be able to uncheck this checkbox'}
        vendor_branch_map = {}
        vendor_branch_map[0] = branch_list
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                branchObj = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor = vendorobj).order_by('name')
                vendor_branch_map[vendorobj.pk] = branchObj
        branch_location_map = {}
        branch_location_map['0'] = locationlist
        if branch_list:
            for branch in branch_list:
                locationlist = Location.objects.filter(branch = branch)
                branch_location_map[branch.pk]=locationlist
        vendor_customergroup_map = {}
        vendor_customergroup_map['0'] = customergroup_list
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                customergroupObj = CustomerGroup.objects.filter(tenant = adminobj.tenant, is_active = True, vendor = vendorobj).order_by('name') 
                vendor_customergroup_map[vendorobj.pk] = customergroupObj
        context['vendor_customergroup_map'] = vendor_customergroup_map
        context['vendor_branch_map'] = vendor_branch_map
        context['branch_location_map'] = branch_location_map
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCustomerDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCustomerDetails, self).get_form_kwargs()
        customer_name_list = []
        customer_phone_list = []
        customer_alt_phone_list = []
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        customer_list = Customer.objects.filter(branch__tenant = admin_user.tenant)
        for customer in customer_list:
            customer_name_list.append(customer.get_name_address_value())
            customer_phone_list.append(customer.phone)
            customer_alt_phone_list.append(customer.alt_phone)
        kw['customer_name_list'] = customer_name_list
        kw['customer_phone_list'] = customer_phone_list
        kw['customer_alt_phone_list'] = customer_alt_phone_list
        customer_details = Customer.objects.get(pk = self.kwargs['pk'])
        kw['customer_details'] = customer_details
        return kw

    def form_valid(self, form):
        form.instance.status = CustomerStatus.objects.get(name = 'Approved')
        form.instance.phone = validate_mobile_countryCode(self.request.POST.get('phone'))
        form.instance.alt_phone = validate_mobile_countryCode(self.request.POST.get('alt_phone'))
        working_time_end = self.request.POST.get('working_time_end')
        working_time_start = self.request.POST.get('working_time_start')
        if working_time_end and working_time_start:
            working_time_end = convert_time_str_to_time_arr(working_time_end)
            hours = int(working_time_end[0]) * 60
            minutes = int(working_time_end[1])
            working_time_end_in_minutes = hours + minutes
            working_time_start = convert_time_str_to_time_arr(working_time_start)
            hours = int(working_time_start[0]) * 60
            minutes = int(working_time_start[1])
            working_time_start_in_minutes = hours + minutes
            form.instance.working_start_time = working_time_start_in_minutes
            form.instance.working_end_time = working_time_end_in_minutes
        return super(UpdateCustomerDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        request.session['active_tab'] = '0'
        customerObj = Customer.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Customer details sucessfully!'
        return super(UpdateCustomerDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_customers')
        #return reverse('administrations:list_customers', kwargs={'pk':self.object.pk})

@class_view_decorator(login_required)
class ListSkills(AdminListView):
    model = Skill
    template_name = 'list_skills.html'

    def get(self, request, *args, **kwargs):
        return super(ListSkills, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplaySkillDetails(AdminTemplateView):
    template_name = 'display_skill_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplaySkillDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        skill_details = Skill.objects.get(pk = kwargs['pk'])
        self.skill_details = skill_details
        return super(DisplaySkillDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateSkill(AdminCreateView):
    model = Skill
    form_class = CreateSkillForm
    template_name = 'create_skill.html'
    success_message = 'New Skill created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateSkill,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateSkill, self).get_form_kwargs()
        return kw

    def form_valid(self, form):
        return super(CreateSkill,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateSkill, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Skill created successfully'
        return reverse('administrations:list_skills')

@class_view_decorator(login_required)
class UpdateSkillDetails(AdminUpdateView):
    model = Skill
    form_class = UpdateSkillDetailForm
    template_name = 'update_skill_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSkillDetails,self).get_context_data(**kwargs)
        skillObj = Skill.objects.get(pk = self.kwargs['pk'])
        context['skillObj'] = skillObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateSkillDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateSkillDetails, self).get_form_kwargs()
        skill_details = Skill.objects.get(pk = self.kwargs['pk'])
        kw['skill_details'] = skill_details
        return kw

    def post(self, request, *args, **kwargs):
        skillObj = Skill.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Skill details sucessfully!'
        return super(UpdateSkillDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_skills')

@class_view_decorator(login_required)
class ListBranches(AdminListView):
    model = Branch
    template_name = 'list_branches.html'

    def get_context_data(self, **kwargs):
        context = super(ListBranches,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Branch.objects.filter(tenant = admin_user.tenant, vendor = self.kwargs['vendor_id'])
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListBranches, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayBranchDetails(AdminTemplateView):
    template_name = 'display_branch_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayBranchDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        branch_details = Branch.objects.get(pk = kwargs['pk'])
        self.branch_details = branch_details
        return super(DisplayBranchDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateBranch(AdminCreateView):
    model = Branch
    form_class = CreateBranchForm
    template_name = 'create_branch.html'

    def get_context_data(self, **kwargs):
        context = super(CreateBranch,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        region_details = Region.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        state_details = State.objects.filter(is_active = True).order_by('name')
        context['form'].fields['region'].queryset =  region_details
        context['form'].fields['state'].queryset =  state_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateBranch,self).form_valid(form)
        
    def get_form_kwargs(self):
        kw = super(CreateBranch, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor_id'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateBranch, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Branch created successfully'
        return reverse('administrations:list_branches', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateBranchDetails(AdminUpdateView):
    model = Branch
    form_class = UpdateBranchDetailForm
    template_name = 'update_branch_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateBranchDetails,self).get_context_data(**kwargs)
        branchObj = Branch.objects.get(pk = self.kwargs['pk'])
        context['branchObj'] = branchObj
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateBranchDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateBranchDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        branch_details = Branch.objects.get(pk = self.kwargs['pk'])
        kw['branch_details'] = branch_details
        kw['vendor_id'] = self.kwargs['vendor_id']
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateBranchDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        branchObj = Branch.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Branch details sucessfully!'
        return super(UpdateBranchDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_branches', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class ListEngineers(AdminListView):
    model = Engineer
    template_name = 'list_engineers.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        if len(self.request.session.get('user_vendor_list')) > 0:
            queryset = Engineer.objects.filter(Q(vendors__in = self.request.session.get('user_vendor_list'))|Q(vendors = None), tenant = admin_user.tenant).distinct()
        else:
            queryset = Engineer.objects.filter(tenant = admin_user.tenant)
        return queryset
            
    def get(self, request, *args, **kwargs):
        return super(ListEngineers, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateEngineer(AdminCreateView):
    model = Engineer
    form_class = CreateEngineerForm
    template_name = 'create_engineer.html'
    success_message = 'New Engineer created successfully'

    def get_form_kwargs(self):
        kw = super(CreateEngineer, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)  
        engineer_mobile_number_list = []
        engineer_alt_phone_list = []
        engineer_mobile_number_details = Engineer.objects.filter(tenant = admin_user.tenant)
        for engineer in engineer_mobile_number_details:
            engineer_mobile_number_list.append(engineer.mobile_number)
            engineer_alt_phone_list.append(engineer.alt_phone)
        kw['engineer_mobile_number_list'] = engineer_mobile_number_list
        kw['engineer_alt_phone_list'] = engineer_alt_phone_list
        kw['vendor_id'] = 1
        kw['vendor_list'] = self.request.session.get('user_vendor_list')
        kw['tenant'] = admin_user.tenant
        return kw

    def get_context_data(self, **kwargs):
        context = super(CreateEngineer,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        user_status_details = UserStatus.objects.filter(tenant = admin_user.tenant, is_active = True)
        branchObj = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        locationlist = Location.objects.filter(branch__in = branchObj).order_by('name')
        reporting_manager_details = Engineer.objects.filter(tenant = admin_user.tenant, is_manager = True, status__is_active_status = True).order_by('first_name')
        designation_details = Designation.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        vendor_list = self.request.session.get('user_vendor_list') 
        vendor_details = Vendor.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        if vendor_list:
            vendor_details = vendor_details.filter(pk__in = vendor_list)
            branchObj = branchObj.filter(vendor__in = vendor_list)
            if len(vendor_details) == 1:
                context['form'].fields['vendors'].initial = vendor_details
            context['form'].fields['vendors'].queryset = vendor_details
        vendor_branch_map = {}
        vendor_branch_map['0'] = branchObj
        for vendor in vendor_details:
            branch_details = branchObj.filter(vendor = vendor)
            vendor_branch_map[vendor.id] = branch_details
        branch_location_map = {}
        branch_location_map['0'] = locationlist
        if branchObj:
            for branch in branchObj:
                locationlist = Location.objects.filter(branch = branch)
                branch_location_map[branch.pk]=locationlist
        context['vendor_branch_map'] = vendor_branch_map
        context['branch_location_map'] = branch_location_map
        context['vendor_id'] = 1
        context['vendor_list'] = vendor_list
        #context['form'].fields['branch'].queryset =  branch_details
        context['form'].fields['status'].queryset = user_status_details
        context['form'].fields['reporting_manager'].queryset =  reporting_manager_details
        context['form'].fields['designation'].queryset =  designation_details
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        entered_username = generate_username(form.instance.email)
        user_name =  entered_username
        form.instance.username = user_name
        form.instance.password = 'pbkdf2_sha256$150000$l2J2JHlCRZtB$94BfsvihpBPrhreFGH+UOGFJtFCjiYSTh1pH3ZELlic='
        form.instance.tenant = adminobj.tenant
        form.instance.reset_password_on_next_login = True
        form.instance.join_date = datetime.now().date()
        form.instance.mobile_number = validate_mobile_countryCode(self.request.POST.get('mobile_number'))
        form.instance.alt_phone = validate_mobile_countryCode(self.request.POST.get('alt_phone'))
        return super(CreateEngineer,self).form_valid(form)
        
    def get(self, request, *args, **kwargs):
        return super(CreateEngineer, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Engineer created successfully'
        vendor_list = self.request.session.get('user_vendor_list') 
        engineerObj = Engineer.objects.get(pk = self.object.pk)
        if vendor_list:
            if not engineerObj.vendors.exists():
                vendorObj = Vendor.objects.filter(pk__in = vendor_list)
                engineerObj.vendors.add(*vendorObj)
        return reverse('administrations:list_engineers')

@class_view_decorator(login_required)
class DisplayEngineerDetails(AdminTemplateView):
    template_name = 'display_engineer_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayEngineerDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        engineer_details = Engineer.objects.get(pk = self.kwargs['pk'])
        self.engineer_details = engineer_details
        return super(DisplayEngineerDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateEngineerDetails(AdminUpdateView):
    model = Engineer
    form_class = UpdateEngineerDetailForm
    template_name = 'update_engineer_details.html'
    callobj = None

    def get_context_data(self, **kwargs):
        context = super(UpdateEngineerDetails,self).get_context_data(**kwargs)
        self.callobj = Engineer.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = self.callobj
        engineerObj = Engineer.objects.get(pk = self.kwargs['pk'])
        context['engineerObj'] = engineerObj
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        user_status_details = UserStatus.objects.filter(tenant = admin_user.tenant, is_active = True)
        #branch_details = Branch.objects.filter(is_active = True).order_by('name')
        reporting_manager_details = Engineer.objects.filter(tenant = admin_user.tenant, is_manager = True,status__is_active_status = True).order_by('first_name')
        designation_details = Designation.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        vendor_list = self.request.session.get('user_vendor_list') 
        branchObj = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        locationlist = Location.objects.filter(branch__in = branchObj).order_by('name')
        vendor_details = Vendor.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        if vendor_list:
            vendor_details = vendor_details.filter(pk__in = vendor_list)
            branchObj = branchObj.filter(vendor__in = vendor_list)
            if len(vendor_details) == 1:
                context['form'].fields['vendors'].initial = vendor_details
            context['form'].fields['vendors'].queryset = vendor_details
        vendor_branch_map = {}
        branch_list = []
        vendor_branch_map['0'] = branchObj
        for vendor in vendor_details:
            branch_details = branchObj.filter(vendor = vendor)
            vendor_branch_map[vendor.id] = branch_details
        branch_location_map = {}
        branch_location_map['0'] = locationlist
        if branchObj:
            for branch in branchObj:
                locationlist = Location.objects.filter(branch = branch)
                branch_location_map[branch.pk]=locationlist
        context['vendor_branch_map'] = vendor_branch_map
        context['branch_location_map'] = branch_location_map
        context['vendor_id'] = 1
        context['vendor_list'] = vendor_list
        context['form'].fields['access_branches'].initial = admin_user.access_branches
        context['form'].fields['status'].queryset = user_status_details
        context['form'].fields['reporting_manager'].queryset =  reporting_manager_details
        context['form'].fields['designation'].queryset =  designation_details
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateEngineerDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateEngineerDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)  
        engineer_details = Engineer.objects.get(pk = self.kwargs['pk'])
        engineer_mobile_number_list = []
        engineer_alt_phone_list = []
        engineer_mobile_number_details = Engineer.objects.filter(tenant = admin_user.tenant)
        for engineer in engineer_mobile_number_details:
            engineer_mobile_number_list.append(engineer.mobile_number)
            engineer_alt_phone_list.append(engineer.alt_phone)
        kw['engineer_mobile_number_list'] = engineer_mobile_number_list
        kw['engineer_alt_phone_list'] = engineer_alt_phone_list
        kw['engineer_details'] = engineer_details
        kw['vendor_id'] = 1
        kw['vendor_list'] = self.request.session.get('user_vendor_list')
        return kw
    
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.mobile_number = validate_mobile_countryCode(self.request.POST.get('mobile_number'))
        form.instance.alt_phone = validate_mobile_countryCode(self.request.POST.get('alt_phone'))
        return super(UpdateEngineerDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Engineer details sucessfully!'
        return super(UpdateEngineerDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        engObj = Engineer.objects.get(pk = self.kwargs['pk'])
        user_vendor_list = self.request.session.get('user_vendor_list') 
        vendor_list = self.request.POST.getlist('vendors')
        if vendor_list:
            vendorObj = Vendor.objects.filter(pk__in = vendor_list)
            for vendor in vendorObj:
                if not engObj.vendors == vendor:
                    engObj.vendors.add(vendor)                   
        else:
            if user_vendor_list:
                vendorObj = Vendor.objects.filter(pk__in = user_vendor_list)
                if vendorObj:
                    engObj.vendors.add(*vendorObj)
        return reverse('administrations:list_engineers')
    
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateCallTicket(AdminCreateView):
    model = CallTicket
    form_class = CreateCallDetailsForm
    template_name = 'create_call_ticket.html'
    machine = None

    def get_context_data(self, **kwargs):
        context = super(CreateCallTicket,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        branch_list_all = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        customer_list = Customer.objects.filter(branch__tenant = admin_user.tenant).order_by('name')
        machine_list_all = Machine.objects.filter(customer__branch__tenant = admin_user.tenant, status__name = 'Approved').order_by('serial_number')
        call_type_list_all = CallType.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        call_classification_list_all = CallClassification.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        ticket_type_list = TicketType.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        severity_level_list = SeverityLevel.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        vendor_list = self.request.session['vendors_with_create_call_list']
        if self.request.session['customer_admin']:
            vendor_list = []
            for vendor in self.request.session['user_vendors']:
                vendor_list.append(vendor.pk)
        customer_machine_map = {}
        customer_sla_list_map = {}
        vendor_sla_list_map = {}
        customer_machine_map[-1] = list(machine_list_all)
        #customer_sla_list_map[-1] = list(severity_level_list)
        branch_customer_map = {}
        vendor_branch_map = {}
        vendor_call_type_map = {}
        vendor_call_type_map[-1] = []
        vendor_call_classification_map = {}
        vendor_call_classification_map[-1] = []
        vendor_branch_map[-1] = []
        branch_customer_map[-1] = list(customer_list)
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                branch_list = Branch.objects.filter(vendor = vendorobj, tenant = admin_user.tenant, is_active = True).order_by('name')
                call_type_list = CallType.objects.filter(vendor = vendorobj, tenant = admin_user.tenant, is_active = True).order_by('rank')
                call_classification_list = CallClassification.objects.filter(vendor = vendorobj, tenant = admin_user.tenant, is_active = True).order_by('rank')
                vendor_branch_map[vendorobj.pk] = list(branch_list)
                vendor_call_type_map[vendorobj.pk] = list(call_type_list)
                vendor_call_classification_map[vendorobj.pk] = list(call_classification_list)
                severity_level_list_vendor = []
                severity_label_vendor= 'Severity'
                tenantvendormappingobj = TenantVendorMapping.objects.filter(vendor = vendorobj, tenant = admin_user.tenant).first()
                if tenantvendormappingobj.severity_based_sla_applicable:
                    severity_level_list_vendor= SeverityLevel.objects.filter(is_active = True, vendor = vendorobj).order_by('name')
                    if tenantvendormappingobj.severity_name:
                        severity_label_vendor = tenantvendormappingobj.severity_name
                tier_list_vendor = []
                tier_label_vendor= 'Tier'
                if tenantvendormappingobj.tier_based_sla_applicable:
                    tier_list_vendor= Tier.objects.filter(is_active = True, vendor = vendorobj).order_by('name')
                    if tenantvendormappingobj.tier_name:
                        tier_label_vendor = tenantvendormappingobj.tier_name
                department_list_vendor = Department.objects.none()
                department_label_vendor= 'Department'
                if tenantvendormappingobj.department_based_sla_applicable:
                    department_list_vendor= Department.objects.filter(is_active = True, vendor = vendorobj).order_by('name')
                    if tenantvendormappingobj.department_name:
                        department_label_vendor = tenantvendormappingobj.department_name
                location_type_list_vendor = LocationType.objects.none()
                location_type_label_vendor= 'Location Type'
                if tenantvendormappingobj.location_type_based_sla_applicable:
                    location_type_list_vendor= LocationType.objects.filter(is_active = True, vendor = vendorobj).order_by('name')
                    if tenantvendormappingobj.location_type_name:
                        location_type_label_vendor = tenantvendormappingobj.location_type_name
                vendor_sla_list_map[vendorobj.id] = [list(severity_level_list_vendor), severity_label_vendor, list(tier_list_vendor), tier_label_vendor, list(department_list_vendor), department_label_vendor, list(location_type_list_vendor), location_type_label_vendor]
                for branch in branch_list:
                    branch_customer_list =  Customer.objects.filter(branch__tenant = admin_user.tenant, branch = branch).order_by('name') 
                    for customer in branch_customer_list:
                        machine_list = Machine.objects.filter(customer__branch__tenant = admin_user.tenant, customer = customer, status__is_active_status = True).order_by('serial_number')
                        customer_machine_map[customer.id] = list(machine_list)
                        severity_level_list_customer = SeverityLevel.objects.none()
                        severity_label= 'Severity'
                        if customer.severity_based_sla_applicable:
                            severity_level_list_customer= SeverityLevel.objects.filter(is_active = True, customer = customer).order_by('name')
                            if customer.severity_name:
                                severity_label = customer.severity_name
                        tier_list_customer = Tier.objects.none()
                        tier_label= 'Tier'
                        if customer.tier_based_sla_applicable:
                            tier_list_customer= Tier.objects.filter(is_active = True, customer = customer).order_by('name')
                            if customer.tier_name:
                                tier_label = customer.tier_name
                        department_list_customer = Department.objects.none()
                        department_label= 'Department'
                        if customer.department_based_sla_applicable:
                            department_list_customer= Department.objects.filter(is_active = True, customer = customer).order_by('name')
                            if customer.department_name:
                                department_label = customer.department_name
                        location_type_list_customer = LocationType.objects.none()
                        location_type_label= 'Location Type'
                        if customer.location_type_based_sla_applicable:
                            location_type_list_customer= LocationType.objects.filter(is_active = True, customer = customer).order_by('name')
                            if customer.location_type_name:
                                location_type_label = customer.location_type_name
                        customer_sla_list_map[customer.id] = [list(severity_level_list_customer), severity_label, list(tier_list_customer), tier_label, list(department_list_customer), department_label, list(location_type_list_customer), location_type_label]
                    branch_customer_map[branch.id] = list(branch_customer_list)
        context['customer_sla_list_map'] = customer_sla_list_map
        context['customer_machine_map'] = customer_machine_map
        context['branch_customer_map'] = branch_customer_map
        context['vendor_branch_map'] = vendor_branch_map
        context['vendor_sla_list_map'] = vendor_sla_list_map
        context['vendor_call_type_map'] = vendor_call_type_map
        context['vendor_call_classification_map'] = vendor_call_classification_map
        customer_choices = []
        customer_choices.append([-1, '--------------'])
        if self.request.session['customer_admin']:
            for customer in self.request.session['user_customers']:
                customer_choices.append([customer.id, customer.get_customer_branch_value()])
            vendor_temp_list = self.request.session['user_vendors']
            vendor_temp_id_list = []
            for vendor in vendor_temp_list:
                vendor_temp_id_list.append(vendor.pk)
            call_type_list_all = CallType.objects.filter(tenant = admin_user.tenant, is_active = True, vendor__pk__in = vendor_temp_id_list).order_by('rank')
            call_classification_list_all = CallClassification.objects.filter(tenant = admin_user.tenant, is_active = True, vendor__pk__in = vendor_temp_id_list).order_by('rank')
        else :
            for customer in customer_list:
                customer_choices.append([customer.id, customer.get_customer_branch_value()])
        context['form'].fields['customer'].choices =  customer_choices
        context['form'].fields['ticket_type'].queryset =  ticket_type_list
        if ticket_type_list.count() > 1:
            context['form'].fields['ticket_type'].initial = ticket_type_list[1]
        vendor_choices = []
        vendor_choices.append([-1, '--------------'])
        for vendor_id in vendor_list:
            vendorobj = Vendor.objects.filter(pk = vendor_id).first()
            if vendorobj:
                vendor_choices.append([vendorobj.id, vendorobj.name])
        context['form'].fields['vendor'].choices =  vendor_choices       
        hide_vendor = False
        if len(vendor_list) == 1:
            context['form'].fields['vendor'].initial = vendor_list[0]
            branch_list = Branch.objects.filter(tenant = admin_user.tenant, is_active = True, vendor__pk = vendor_list[0]).order_by('name')
            hide_vendor = True
            call_type_list = CallType.objects.filter(tenant = admin_user.tenant, is_active = True, vendor__pk = vendor_list[0]).order_by('rank')
        context['hide_vendor'] = hide_vendor
        branch_choices = []
        branch_choices.append([-1, '--------------'])
        for branch in branch_list_all:
            branch_choices.append([branch.id, branch.get_branch_vendor_value()])
        context['form'].fields['branch'].choices =  branch_choices
        if self.request.session['customer_admin']:
            customer_list  = self.request.session['user_customers']
            context['form'].fields['branch'].initial = customer_list[0].branch.pk 
        machine_choices = []
        machine_choices.append([-1, '--------------'])
        for machine in machine_list_all:
            machine_choices.append([machine.id, machine])
        context['form'].fields['machine'].choices =  machine_choices
        context['form'].fields['call_type'].queryset =  call_type_list_all
        context['form'].fields['call_classification'].queryset =  call_classification_list_all
        today = datetime.now() + timedelta(minutes = 330)
        context['form'].fields['vendor_create_date_component'].initial = today.date()
        context['form'].fields['vendor_create_time_component'].initial = today.strftime('%I:%M %p')
        return context

    def get_form_kwargs(self):
        kw = super(CreateCallTicket, self).get_form_kwargs()
        customer_admin = self.request.session['customer_admin']
        kw['customer_admin'] = customer_admin
        return kw
    
    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        callstatusobj = CallStatus.objects.filter(tenant = admin_user.tenant, is_initial_status = True).first()
        if callstatusobj:
            form.instance.status = callstatusobj
        form.instance.tenant_id = admin_user.tenant.id          
        customer_id = self.request.POST.get('customer')
        if customer_id:
            customerobj = Customer.objects.filter(pk = customer_id).first()
            if customerobj:
                form.instance.customer_name = customerobj.name
                form.instance.customer_phone = customerobj.phone
                form.instance.customer_alt_phone = customerobj.alt_phone
                form.instance.customer_email = customerobj.email
                form.instance.customer_address = customerobj.address
                form.instance.is_premium_customer = customerobj.is_premium
                form.instance.customer_address_latitude = customerobj.address_latitude
                form.instance.customer_address_longitude = customerobj.address_longitude
                form.instance.customer_spoc_name = customerobj.spoc_name
                if customerobj.is_auto_appointment_allowed:
                    form.instance.is_auto_appointment = True
                if self.request.session['customer_admin']:
                    form.instance.vendor = customerobj.branch.vendor
                    form.instance.branch = customerobj.branch               
        vendor_create_date_component_str = self.request.POST.get('vendor_create_date_component')
        vendor_create_time_component_str = self.request.POST.get('vendor_create_time_component')
        vendor_crm_ticket_time = None
        if vendor_create_date_component_str and vendor_create_time_component_str:
            vendor_create_date_component = parser.parse(vendor_create_date_component_str)
            vendor_create_time_component = convert_time_str_to_time_arr(vendor_create_time_component_str)
            vendor_crm_ticket_time = datetime(year = vendor_create_date_component.year, month = vendor_create_date_component.month, day = vendor_create_date_component.day, hour = vendor_create_time_component[0], minute = vendor_create_time_component[1], tzinfo = timezone.utc)
            vendor_crm_ticket_time -= timedelta(minutes = 330)
        form.instance.vendor_crm_ticket_time = vendor_crm_ticket_time
        return super(CreateCallTicket,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.machine = request.POST.get('machine')
        self.success_message = 'Call Ticket created sucessfully!'
        return super(CreateCallTicket, self).post(request, args, kwargs)

    def get_success_url(self):
        callobj = CallTicket.objects.get(pk = self.object.pk)
        updating_user = HCMSUser.objects.get(pk = self.request.user.pk)
        status_track = TicketStatusTrack(ticket = callobj, new_status = callobj.status, new_reason_code = callobj.reason_code, notes = 'New Ticket Created', status_changed_by = updating_user, status_change_time = callobj.created_time)
        status_track.save()
        if self.machine:
            machineobj = Machine.objects.filter(pk = self.machine).first()
            if machineobj:
                ticket_machine = TicketMachineDetails(serial_number = machineobj.serial_number, mtm_number = machineobj.mtm_number, warranty_type = machineobj.warranty_type, warranty_details = machineobj.warranty_details, amc_start_date = machineobj.amc_start_date, amc_end_date = machineobj.amc_end_date, hard_disk_retention = machineobj.hard_disk_retention, accident_damage_cover = machineobj.accident_damage_cover,  customer_induced_damage = machineobj.customer_induced_damage, cru_machine = machineobj.cru_machine, assest_id = machineobj.assest_id, user_name = machineobj.user_name, user_employee_id = machineobj.user_employee_id, user_designation = machineobj.user_designation, location = machineobj.location, floor = machineobj.floor, building_name = machineobj.building_name, reporting_manager_email = machineobj.reporting_manager_email, processor_speed = machineobj.processor_speed, monitor_make = machineobj.monitor_make, monitor_size = machineobj.monitor_size, host_name = machineobj.host_name, mac_address = machineobj.mac_address, ip_address = machineobj.ip_address, anti_virus_name = machineobj.anti_virus_name, anti_virus_serial_number = machineobj.anti_virus_serial_number, anti_virus_key = machineobj.anti_virus_key, anti_virus_expiry_date = machineobj.anti_virus_expiry_date, operating_system = machineobj.operating_system, ram_type = machineobj.ram_type, hard_disk_type = machineobj.hard_disk_type, softwares = machineobj.softwares, ticket_id = self.object.pk)
                if machineobj.model:
                    ticket_machine.custom_machine_type = machineobj.model.machine_type.name
                    ticket_machine.custom_make = machineobj.model.machine_make.name
                    ticket_machine.custom_model = machineobj.model.name
                ticket_machine.save()
        return reverse('administrations:display_call_ticket_details', kwargs={'pk':self.object.pk})


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallDetails(AdminUpdateView):
    model = CallTicket
    form_class = EditCallDetailsForm
    template_name = 'edit_call_details.html'
    success_message = 'Call details updated sucessfully!'
    callobj = None
    notes = None

    def get_context_data(self, **kwargs):
        context = super(EditCallDetails,self).get_context_data(**kwargs)
        self.callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = self.callobj
        status_choices = []
        transition_pks = [self.callobj.status.pk]
        transition_status_list = self.callobj.status.transition_statuses.all()
        for transition_status in transition_status_list:
            transition_pks.append(transition_status.pk)
        status_list = CallStatus.objects.filter(pk__in = transition_pks, is_active = True).order_by('rank')
        for statusobj in status_list:
            status_choices.append([statusobj.id, statusobj.name])
        context['form'].fields['status'].choices =  status_choices
        branch_list = Branch.objects.filter(tenant = self.callobj.tenant).order_by('name')
        if self.callobj.vendor:
            branch_list = Branch.objects.filter(tenant = self.callobj.tenant, vendor = self.callobj.vendor).order_by('name')
        queue_list = Queue.objects.filter(tenant = self.callobj.tenant).order_by('name')
        if len(self.request.session['user_queues']) > 0:
            queue_list = self.request.session['user_queues']
        engineer_list = Engineer.objects.filter(Q(access_branches = self.callobj.branch) | Q(access_branches__isnull = True)).order_by('first_name', 'last_name')
        context['form'].fields['assigned_engineer'].queryset = engineer_list
        branch_engineer_map = {}
        branch_engineer_map[-1] = Engineer.objects.filter(branch__tenant = self.callobj.tenant, vendors = self.callobj.vendor).order_by('first_name', 'last_name')
        branch_choices = []
        branch_choices.append([-1, '--------------'])
        if self.callobj.customer and self.callobj.customer.location:
            for branch in branch_list:
                engineer_list = Engineer.objects.filter(Q(access_branches = self.callobj.branch) | Q(access_branches__isnull = True), Q(vendors = self.callobj.vendor) | Q(vendors__isnull = True), Q(access_locations = self.callobj.customer.location) | Q(access_locations__isnull = True)).order_by('first_name', 'last_name')
                branch_engineer_map[branch.pk] = list(engineer_list)
                branch_choices.append([branch.pk, branch.name])
        else:
            for branch in branch_list:
                engineer_list = Engineer.objects.filter(Q(access_branches = branch) | Q(access_branches__isnull = True), Q(vendors = self.callobj.vendor) | Q(vendors__isnull = True)).order_by('first_name', 'last_name')
                branch_engineer_map[branch.pk] = list(engineer_list)
                branch_choices.append([branch.pk, branch.name])
        queue_engineer_map = {}    
        queue_engineer_map['-1'] = []    
        queue_choices = []
        queue_choices.append(['-1', '--------------'])
        for queue in queue_list:
            admin_list = Administrator.objects.filter(Q(access_queues = queue)|Q(access_queues__isnull = True), is_active =True, tenant = self.callobj.tenant).order_by('first_name', 'last_name')
            admin_id_list = []
            for admin in admin_list:
                admin_id_list.append(admin.pk)        
            if len(admin_id_list) > 0:
                engineer_queue_list = Engineer.objects.filter(pk__in = admin_id_list)
                queue_engineer_map[queue.pk] = list(engineer_queue_list)
            else:    
                queue_engineer_map[queue.pk] = []
            queue_choices.append([queue.pk, queue.name])    
        context['form'].fields['branch'].choices = branch_choices
        context['form'].fields['queue'].choices = queue_choices
        context['branch_engineer_map']= branch_engineer_map
        context['queue_engineer_map']= queue_engineer_map
        context['form'].fields['vendor'].queryset = Vendor.objects.filter(tenant = self.callobj.tenant).order_by('name')
        call_type_list = CallType.objects.filter(tenant = self.callobj.tenant, is_active = True).order_by('name')
        call_classification_list = CallClassification.objects.filter(tenant = self.callobj.tenant, is_active = True).order_by('name')
        vendor_support_list = VendorSupport.objects.filter(tenant = self.callobj.tenant, is_active = True).order_by('vendor_name')
        context['form'].fields['assigned_vendor_support'].queryset = vendor_support_list
        if self.callobj.vendor:
            call_type_list = CallType.objects.filter(tenant = self.callobj.tenant, vendor = self.callobj.vendor, is_active = True).order_by('name')
            call_classification_list = CallClassification.objects.filter(tenant = self.callobj.tenant, vendor = self.callobj.vendor, is_active = True).order_by('name')
        context['form'].fields['call_type'].queryset = call_type_list
        context['form'].fields['call_classification'].queryset = call_classification_list
        context['form'].fields['ticket_type'].queryset = TicketType.objects.filter(tenant = self.callobj.tenant).order_by('name')
        severity_level_label = ''
        tier_label = ''
        department_label = ''
        location_type_label = ''
        if self.callobj.customer:
            context['form'].fields['severity_level'].queryset = SeverityLevel.objects.filter(customer = self.callobj.customer).order_by('name')       
            context['form'].fields['tier'].queryset = Tier.objects.filter(customer = self.callobj.customer).order_by('name')        
            context['form'].fields['department'].queryset = Department.objects.filter(customer = self.callobj.customer).order_by('name')
            context['form'].fields['location_type'].queryset = LocationType.objects.filter(customer = self.callobj.customer).order_by('name')
            severity_level_label = self.callobj.customer.severity_name
            tier_label = self.callobj.customer.tier_name
            department_label = self.callobj.customer.department_name
            location_type_label = self.callobj.customer.location_type_name
        else:
            context['form'].fields['severity_level'].queryset = SeverityLevel.objects.filter(vendor = self.callobj.vendor).order_by('name')       
            context['form'].fields['tier'].queryset = Tier.objects.filter(vendor = self.callobj.vendor).order_by('name')        
            context['form'].fields['department'].queryset = Department.objects.filter(vendor = self.callobj.vendor).order_by('name')
            context['form'].fields['location_type'].queryset = LocationType.objects.filter(vendor = self.callobj.vendor).order_by('name')
            tenantvendormappingobj = TenantVendorMapping.objects.filter(tenant = self.callobj.tenant, vendor = self.callobj.vendor).first()
            severity_level_label = tenantvendormappingobj.severity_name
            tier_label = tenantvendormappingobj.tier_name
            department_label = tenantvendormappingobj.department_name
            location_type_label = tenantvendormappingobj.location_type_name
        context['severity_level_label'] = severity_level_label    
        context['tier_label'] = tier_label    
        context['department_label'] = department_label 
        context['location_type_label'] = location_type_label   
        if self.callobj.appointment_time:
            appointment_time = self.callobj.appointment_time + timedelta(minutes = 330)
            context['form'].fields['appointment_date_component'].initial = appointment_time.date()
            context['form'].fields['appointment_time_component'].initial = appointment_time.strftime('%I:%M %p')
        if self.callobj.vendor_crm_ticket_time:
            vendor_crm_ticket_time = self.callobj.vendor_crm_ticket_time + timedelta(minutes = 330)
            context['form'].fields['vendor_create_date_component'].initial = vendor_crm_ticket_time.date()
            context['form'].fields['vendor_create_time_component'].initial = vendor_crm_ticket_time.strftime('%I:%M %p')
        context['form'].fields['engineer_type'].initial = '1'
        if self.callobj.assigned_vendor_support:
            context['form'].fields['engineer_type'].initial = '2'
        return context

    def get_form_kwargs(self):
        kw = super(EditCallDetails, self).get_form_kwargs()
        ticketobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        kw['ticketobj'] = ticketobj
        return kw

    def post(self, request, *args, **kwargs):
        if not self.callobj:
            self.callobj = CallTicket.objects.get(pk = kwargs['pk'])
        self.notes = request.POST.get('notes', '')
        self.status = None
        self.reason_code = None
        status_id = request.POST.get('status', '')
        if status_id:
            self.status = CallStatus.objects.get(pk = status_id)
        reason_code_id = request.POST.get('reason_code', '')
        if reason_code_id:
            self.reason_code = ReasonCode.objects.get(pk = reason_code_id)
        return super(EditCallDetails, self).post(request, args, kwargs)

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant_id = admin_user.tenant.id          
        appointment_date_component_str = self.request.POST.get('appointment_date_component')
        appointment_time_component_str = self.request.POST.get('appointment_time_component')
        appointment_time = None
        if appointment_date_component_str and appointment_time_component_str:
            appointment_date_component = parser.parse(appointment_date_component_str)
            appointment_time_component = convert_time_str_to_time_arr(appointment_time_component_str)
            appointment_time = datetime(year = appointment_date_component.year, month = appointment_date_component.month, day = appointment_date_component.day, hour = appointment_time_component[0], minute = appointment_time_component[1], tzinfo = timezone.utc)
            appointment_time -= timedelta(minutes = 330)
        form.instance.appointment_time = appointment_time
        updating_user = HCMSUser.objects.get(pk = self.request.user.pk)
        if self.status != self.callobj.status or self.reason_code != self.callobj.reason_code:
            status_track = TicketStatusTrack(ticket = self.callobj, new_status = self.status, new_reason_code = self.reason_code, notes = self.notes, status_changed_by = updating_user, status_change_time = timezone.now())
            status_track.save()
        engineer_type = self.request.POST.get('engineer_type')
        assigned_engineer = self.request.POST.get('assigned_engineer')
        assigned_vendor_support = self.request.POST.get('assigned_vendor_support')
        if engineer_type == '1':
            form.instance.assigned_vendor_support_id = None
        elif engineer_type == '2':
            form.instance.assigned_engineer_id = None
        vendor_create_date_component_str = self.request.POST.get('vendor_create_date_component')
        vendor_create_time_component_str = self.request.POST.get('vendor_create_time_component')
        vendor_crm_ticket_time = None
        if vendor_create_date_component_str and vendor_create_time_component_str:
            vendor_create_date_component = parser.parse(vendor_create_date_component_str)
            vendor_create_time_component = convert_time_str_to_time_arr(vendor_create_time_component_str)
            vendor_crm_ticket_time = datetime(year = vendor_create_date_component.year, month = vendor_create_date_component.month, day = vendor_create_date_component.day, hour = vendor_create_time_component[0], minute = vendor_create_time_component[1], tzinfo = timezone.utc)
            vendor_crm_ticket_time -= timedelta(minutes = 330)
        form.instance.vendor_crm_ticket_time = vendor_crm_ticket_time
        return super(EditCallDetails, self).form_valid(form)

    def get_success_url(self):
        # enter data in audit if anything changed
        updated_callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        updating_user = HCMSUser.objects.get(pk = self.request.user.pk)
        make_audit_entry = False
        audit_json = []
        if updated_callobj.assigned_engineer != self.callobj.assigned_engineer:
            if updated_callobj.assigned_engineer:
                if not AssignedEngineerTrack.objects.filter(engineer = updated_callobj.assigned_engineer, ticket = updated_callobj, appointment_time = updated_callobj.appointment_time, modified_by = updated_callobj.assigned_engineer, is_help_desk_notificed = 'f').exists():
                    assignedengineertrack_obj = AssignedEngineerTrack(engineer = updated_callobj.assigned_engineer, ticket = updated_callobj, appointment_time = updated_callobj.appointment_time, assigned_status = updated_callobj.ASSIGNED_STATUS_ASSIGNED, modified_by = updating_user)
                    assignedengineertrack_obj.save()
                    updated_callobj.auto_assigned_status = updated_callobj.ASSIGNED_STATUS_ASSIGNED
                    updated_callobj.save()
        if updated_callobj.status != self.callobj.status:
            make_audit_entry = True
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Status", "field_name":"status", "old_value":self.callobj.status.name, "new_value":updated_callobj.status.name})
        if updated_callobj.reason_code != self.callobj.reason_code:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.reason_code:
                old_value = self.callobj.reason_code.name
            new_value = 'Blank'
            if updated_callobj.reason_code:
                new_value = updated_callobj.reason_code.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Reason Code", "field_name":"reason_code", "old_value":old_value, "new_value":new_value})
        if updated_callobj.assigned_engineer != self.callobj.assigned_engineer:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.assigned_engineer:
                old_value = self.callobj.assigned_engineer.first_name + ' '+ self.callobj.assigned_engineer.last_name
            new_value = 'Blank'
            if updated_callobj.assigned_engineer:
                new_value = updated_callobj.assigned_engineer.first_name + ' '+ updated_callobj.assigned_engineer.last_name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Assigned Engineer", "field_name":"assigned_engineer", "old_value":old_value, "new_value":new_value})
        if updated_callobj.branch != self.callobj.branch:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.branch:
                old_value = self.callobj.branch.name
            new_value = 'Blank'
            if updated_callobj.branch:
                new_value = updated_callobj.branch.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Branch", "field_name":"branch", "old_value":old_value, "new_value":new_value})
        if updated_callobj.call_type != self.callobj.call_type:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.call_type:
                old_value = self.callobj.call_type.name
            new_value = 'Blank'
            if updated_callobj.ticket_type:
                new_value = updated_callobj.call_type.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Call Type", "field_name":"call_type", "old_value":old_value, "new_value":new_value})
        if updated_callobj.call_classification != self.callobj.call_classification:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.call_classification:
                old_value = self.callobj.call_classification.name
            new_value = 'Blank'
            if updated_callobj.call_classification:
                new_value = updated_callobj.call_classification.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Call Classification", "field_name":"call_classification", "old_value":old_value, "new_value":new_value})
        if updated_callobj.dependency != self.callobj.dependency:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.get_dependency_display():
                old_value = self.callobj.get_dependency_display()
            new_value = 'Blank'
            if updated_callobj.get_dependency_display():
                new_value = updated_callobj.get_dependency_display()
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Dependency", "field_name":"dependency", "old_value":old_value, "new_value":new_value})
        if updated_callobj.dependency_details != self.callobj.dependency_details:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.dependency_details:
                old_value = self.callobj.dependency_details
            new_value = 'Blank'
            if updated_callobj.dependency_details:
                new_value = updated_callobj.dependency_details
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Dependency Details", "field_name":"dependency_details", "old_value":old_value, "new_value":new_value})
        if updated_callobj.ticket_type != self.callobj.ticket_type:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.ticket_type:
                old_value = self.callobj.ticket_type.name
            new_value = 'Blank'
            if updated_callobj.ticket_type:
                new_value = updated_callobj.ticket_type.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Ticket Type", "field_name":"ticket_type", "old_value":old_value, "new_value":new_value})
        if updated_callobj.severity_level != self.callobj.severity_level:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.severity_level:
                old_value = self.callobj.severity_level.name
            new_value = 'Blank'
            if updated_callobj.severity_level:
                new_value = updated_callobj.severity_level.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Severity Level", "field_name":"severity_level", "old_value":old_value, "new_value":new_value})
        if updated_callobj.tier != self.callobj.tier:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.tier:
                old_value = self.callobj.tier.name
            new_value = 'Blank'
            if updated_callobj.tier:
                new_value = updated_callobj.tier.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Tier", "field_name":"tier", "old_value":old_value, "new_value":new_value})
        if updated_callobj.department != self.callobj.department:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.department:
                old_value = self.callobj.department.name
            new_value = 'Blank'
            if updated_callobj.department:
                new_value = updated_callobj.department.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Department", "field_name":"department", "old_value":old_value, "new_value":new_value})
        if updated_callobj.location_type != self.callobj.location_type:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.location_type:
                old_value = self.callobj.location_type.name
            new_value = 'Blank'
            if updated_callobj.location_type:
                new_value = updated_callobj.location_type.name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Location Type", "field_name":"location_type", "old_value":old_value, "new_value":new_value})
        if updated_callobj.reference_number != self.callobj.reference_number:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.reference_number:
                old_value = self.callobj.reference_number
            new_value = 'Blank'
            if updated_callobj.reference_number:
                new_value = updated_callobj.reference_number
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Reference Number", "field_name":"reference_number", "old_value":old_value, "new_value":new_value})
        if updated_callobj.auto_assigned_status != self.callobj.auto_assigned_status: 
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.auto_assigned_status:
                old_value = self.callobj.get_auto_assigned_status_display()
            new_value = 'Blank'
            if updated_callobj.auto_assigned_status:
                new_value = updated_callobj.get_auto_assigned_status_display()
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Auto Assigned Status", "field_name":"auto_assigned_status", "old_value":old_value, "new_value":new_value})
        if updated_callobj.is_auto_assigned != self.callobj.is_auto_assigned: 
            make_audit_entry = True
            old_value = False
            if self.callobj.is_auto_assigned:
                old_value = True
            new_value = False
            if updated_callobj.is_auto_assigned:
                new_value = True
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Auto Assigned Flag", "field_name":"is_auto_assigned", "old_value":old_value, "new_value":new_value})
        if updated_callobj.assigned_vendor_support != self.callobj.assigned_vendor_support:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.assigned_vendor_support:
                old_value = self.callobj.assigned_vendor_support.vendor_name
            new_value = 'Blank'
            if updated_callobj.assigned_vendor_support:
                new_value = updated_callobj.assigned_vendor_support.vendor_name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Assigned Vendor Support", "field_name":"assigned_vendor_support", "old_value":old_value, "new_value":new_value})
        if updated_callobj.assigned_vendor_comments != self.callobj.assigned_vendor_comments:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.assigned_vendor_comments:
                old_value = self.callobj.assigned_vendor_comments
            new_value = 'Blank'
            if updated_callobj.assigned_vendor_comments:
                new_value = updated_callobj.assigned_vendor_comments
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Assigned Vendor Comments", "field_name":"assigned_vendor_comments", "old_value":old_value, "new_value":new_value})
        if updated_callobj.end_user_name != self.callobj.end_user_name:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.end_user_name:
                old_value = self.callobj.end_user_name
            new_value = 'Blank'
            if updated_callobj.end_user_name:
                new_value = updated_callobj.end_user_name
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"End User Name", "field_name":"end_user_name", "old_value":old_value, "new_value":new_value})
        if updated_callobj.end_user_email != self.callobj.end_user_email:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.end_user_email:
                old_value = self.callobj.end_user_email
            new_value = 'Blank'
            if updated_callobj.end_user_email:
                new_value = updated_callobj.end_user_email
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"End User Email", "field_name":"end_user_email", "old_value":old_value, "new_value":new_value})
        if not updated_callobj.appointment_time:
            updated_callobj.appointment_time = ''
        if not self.callobj.appointment_time:
            self.callobj.appointment_time = ''
        if updated_callobj.appointment_time != self.callobj.appointment_time:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.appointment_time:
                old_value =  get_date_disp_value(self.callobj.appointment_time, self.request.session['SHORT_DATE_TIME_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            new_value = 'Blank'
            if updated_callobj.appointment_time:
                new_value = get_date_disp_value(updated_callobj.appointment_time, self.request.session['SHORT_DATE_TIME_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Appointment Time", "field_name":"appointment_time", "old_value":old_value, "new_value":new_value})
        if not updated_callobj.issue_details:
            updated_callobj.issue_details = ''
        if not self.callobj.issue_details:
            self.callobj.issue_details = ''
        if updated_callobj.issue_details != self.callobj.issue_details:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.issue_details:
                old_value =  self.callobj.issue_details
            new_value = 'Blank'
            if updated_callobj.issue_details:
                new_value = updated_callobj.issue_details
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Issue Details", "field_name":"issue_details", "old_value":old_value, "new_value":new_value})
        if not updated_callobj.diagnostic_details:
            updated_callobj.diagnostic_details = ''
        if not self.callobj.diagnostic_details:
            self.callobj.diagnostic_details = ''
        if updated_callobj.diagnostic_details != self.callobj.diagnostic_details:
            make_audit_entry = True
            old_value = 'Blank'
            if self.callobj.diagnostic_details:
                old_value =  self.callobj.diagnostic_details
            new_value = 'Blank'
            if updated_callobj.diagnostic_details:
                new_value = updated_callobj.diagnostic_details
            audit_json.append({"table_name":"CallTicket", "pk":updated_callobj.pk, "display_name":"Diagnostic Details", "field_name":"diagnostic_details", "old_value":old_value, "new_value":new_value})
        if make_audit_entry:
            change_audit = TicketChangesAudit(ticket = updated_callobj, audit_json = json.dumps(audit_json), updated_by = updating_user, updated_time = timezone.now())
            change_audit.save()
        return reverse('administrations:display_call_details', kwargs={'pk':self.kwargs['pk']})

    
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallCustomerDetails(AdminUpdateView):
    model = CallTicket
    form_class = EditCallCustomerDetailForm
    template_name = 'edit_call_customer_details.html'
    success_message = 'Customer details updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(EditCallCustomerDetails,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callobj
        return context

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call details updated sucessfully!'
        return super(EditCallCustomerDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:display_call_customer_details', kwargs={'pk':self.kwargs['pk']})



class DisplayCallDetails(TemplateView):
    template_name = 'call_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallDetails,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callobj
        reason_code_protected_fields = []
        field_reasoncode_list = FieldReasonCodeMap.objects.filter(tenant = callobj.tenant)
        for field_reasoncode in field_reasoncode_list:
            access_field = field_reasoncode.access_field
            if not access_field.field_id in reason_code_protected_fields:
                reason_code_protected_fields.append(access_field.field_id)
        context['reason_code_protected_fields'] = reason_code_protected_fields
        if callobj.customer:
            severity_level_label = callobj.customer.severity_name
            tier_label = callobj.customer.tier_name
            department_label = callobj.customer.department_name
            location_type_label = callobj.customer.location_type_name
        else:
            tenantvendormappingobj = TenantVendorMapping.objects.filter(tenant = callobj.tenant, vendor = callobj.vendor).first()
            severity_level_label = tenantvendormappingobj.severity_name
            tier_label = tenantvendormappingobj.tier_name
            department_label = tenantvendormappingobj.department_name
            location_type_label = tenantvendormappingobj.location_type_name
        context['severity_level_label'] = severity_level_label    
        context['tier_label'] = tier_label    
        context['department_label'] = department_label 
        context['location_type_label'] = location_type_label
        return context

@class_view_decorator(login_required)
class DisplayCallCustomerDetails(AdminTemplateView):
    template_name = 'call_customer_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallCustomerDetails,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callobj
        return context


@class_view_decorator(login_required)
class DisplayCallMachineDetails(AdminTemplateView):
    template_name = 'call_machine_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallMachineDetails,self).get_context_data(**kwargs)
        callmachineobj = TicketMachineDetails.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callmachineobj.ticket
        context['call_machine_obj'] = callmachineobj
        return context


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallMachineDetails(AdminUpdateView):
    model = TicketMachineDetails
    form_class = EditCallMachineDetailForm
    template_name = 'edit_call_machine_details.html'
    success_message = 'Asset details updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(EditCallMachineDetails,self).get_context_data(**kwargs)
        callmachineobj = TicketMachineDetails.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callmachineobj.ticket
        context['call_machine_obj'] = callmachineobj
        return context

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call details updated sucessfully!'
        return super(EditCallMachineDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:display_call_machine_details', kwargs={'pk':self.kwargs['pk']})


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateCallNotesDetails(AdminCreateView):
    model = TicketNotes
    form_class = CreateCallNotesDetailsForm
    template_name = 'create_call_notes.html'
    success_message = 'Call notes created sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(CreateCallNotesDetails,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        return context

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        form.instance.notes_entered_by = admin_user
        form.instance.ticket = callobj
        return super(CreateCallNotesDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call Notes created sucessfully!'
        return super(CreateCallNotesDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        return reverse('administrations:list_call_notes', kwargs={'ticket_id':callobj.pk})

    
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallNotesDetails(AdminUpdateView):
    model = TicketNotes
    form_class = CreateCallNotesDetailsForm
    template_name = 'edit_call_note_details.html'
    success_message = 'Call notes updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(EditCallNotesDetails,self).get_context_data(**kwargs)
        call_notes_obj = TicketNotes.objects.get(pk = self.kwargs['pk'])
        callobj = call_notes_obj.ticket
        context['callobj'] = callobj
        context['call_notes_obj'] = call_notes_obj
        return context

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        form.instance.notes_entered_by = admin_user
        return super(EditCallNotesDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call Notes created sucessfully!'
        return super(EditCallNotesDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        call_notes_obj = TicketNotes.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:list_call_notes', kwargs={'ticket_id':call_notes_obj.ticket.pk})
    

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallLineItemDetails(AdminUpdateView):
    model = TicketLineItem
    form_class = EditCallLineItemForm
    template_name = 'edit_call_line_items.html'
    call_lineitem_obj = None
    success_message = 'Line item details updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(EditCallLineItemDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        call_lineitem_obj = TicketLineItem.objects.get(pk = self.kwargs['pk'])
        callobj = call_lineitem_obj.ticket
        context['callobj'] = callobj
        self.call_lineitem_obj = call_lineitem_obj
        context['call_lineitem_obj'] = call_lineitem_obj
        category_list = LineItemCategory.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        line_item_status_list_all = LineItemStatus.objects.filter(line_item_category__tenant = admin_user.tenant, is_active = True).order_by('rank')
        line_item_dispositioncode_list_all = LineItemDispositionCode.objects.filter(line_item_category__tenant = admin_user.tenant, is_active = True).order_by('rank')
        category_status_map = {}
        category_disposition_map = {}
        category_fields_map = {}
        category_status_map[-1] = list(line_item_status_list_all)
        category_disposition_map[-1] = list(line_item_dispositioncode_list_all)
        for categoryobj in category_list:
            line_item_status_list = LineItemStatus.objects.filter(line_item_category = categoryobj, is_active = True).order_by('rank')
            line_item_dispositioncode_list = LineItemDispositionCode.objects.filter(line_item_category = categoryobj, is_active = True).order_by('rank')
            field_list = FieldLineItemCategoryMap.objects.filter(line_item_category = categoryobj)
            category_status_map[categoryobj.id] = list(line_item_status_list)
            category_disposition_map[categoryobj.id] = list(line_item_dispositioncode_list)
            category_fields_map[categoryobj.id] = list(field_list)
        context['category_status_map'] = category_status_map
        context['category_disposition_map'] = category_disposition_map
        context['category_fields_map'] = category_fields_map
        category_choices = []
        category_choices.append([-1, '--------------'])
        for category in category_list:
            category_choices.append([category.id, category.name])
        context['form'].fields['category'].choices =  category_choices
        protected_fields = []
        field_lineitem_list = FieldLineItemCategoryMap.objects.filter(tenant = admin_user.tenant)
        for field_lineitem in field_lineitem_list:
            access_field = field_lineitem.access_field
            if not access_field.field_id in protected_fields:
                protected_fields.append(access_field.field_id)
        context['protected_fields'] = protected_fields
        line_item_status_list_all = LineItemStatus.objects.filter(line_item_category__tenant = admin_user.tenant, is_active = True).order_by('rank')
        status_disposition_map = {}
        status_disposition_map[0] = line_item_dispositioncode_list_all
        status_choices = []
        status_choices.append([-1, '--------------'])
        for status in category_status_map[call_lineitem_obj.category.id ]:
            status_choices.append([status.id, status.name])
        for status in line_item_status_list_all:
            disposition_details = LineItemDispositionCode.objects.filter(line_item_status=status.id )
            status_disposition_map[status.id] = disposition_details
        context['status_disposition_map'] = status_disposition_map
        context['form'].fields['status'].choices =  status_choices
        return context

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call Line Item updated sucessfully!'
        if not self.call_lineitem_obj:
            self.call_lineitem_obj = TicketLineItem.objects.get(pk = self.kwargs['pk'])
        return super(EditCallLineItemDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        # enter data in audit if anything changed
        updated_lineitem_obj = TicketLineItem.objects.get(pk = self.kwargs['pk'])
        make_audit_entry = False
        audit_json = []
        updating_user = HCMSUser.objects.get(pk = self.request.user.pk)
        if updated_lineitem_obj.status != self.call_lineitem_obj.status:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.status:
                old_value = self.call_lineitem_obj.status.name
            new_value = 'Blank'
            if updated_lineitem_obj.status:
                new_value = updated_lineitem_obj.status.name
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Line Item Status", "field_name":"status", "old_value":old_value, "new_value":new_value})
        if updated_lineitem_obj.category != self.call_lineitem_obj.category:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.category:
                old_value = self.call_lineitem_obj.category.name
            new_value = 'Blank'
            if updated_lineitem_obj.category:
                new_value = updated_lineitem_obj.category.name
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Category", "field_name":"category", "old_value":old_value, "new_value":new_value})
        if updated_lineitem_obj.disposition_code_fsp_dp != self.call_lineitem_obj.disposition_code_fsp_dp:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.disposition_code_fsp_dp:
                old_value = self.call_lineitem_obj.disposition_code_fsp_dp.name
            new_value = 'Blank'
            if updated_lineitem_obj.disposition_code_fsp_dp:
                new_value = updated_lineitem_obj.disposition_code_fsp_dp.name
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Disposition Code FSP DP", "field_name":"disposition_code_fsp_dp", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.other_category:
            updated_lineitem_obj.other_category = ''
        if not self.call_lineitem_obj.other_category:
            self.call_lineitem_obj.other_category = ''
        if updated_lineitem_obj.other_category != self.call_lineitem_obj.other_category:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.other_category:
                old_value = self.call_lineitem_obj.other_category
            new_value = 'Blank'
            if updated_lineitem_obj.other_category:
                new_value = updated_lineitem_obj.other_category
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Other Category", "field_name":"other_category", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.material_id:
            updated_lineitem_obj.material_id = ''
        if not self.call_lineitem_obj.material_id:
            self.call_lineitem_obj.material_id = ''
        if updated_lineitem_obj.material_id != self.call_lineitem_obj.material_id:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.material_id:
                old_value = self.call_lineitem_obj.material_id
            new_value = 'Blank'
            if updated_lineitem_obj.material_id:
                new_value = updated_lineitem_obj.material_id
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Material Id", "field_name":"material_id", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.quantity:
            updated_lineitem_obj.quantity = ''
        if not self.call_lineitem_obj.quantity:
            self.call_lineitem_obj.quantity = ''
        if updated_lineitem_obj.quantity != self.call_lineitem_obj.quantity:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.quantity:
                old_value = self.call_lineitem_obj.quantity
            new_value = 'Blank'
            if updated_lineitem_obj.quantity:
                new_value = updated_lineitem_obj.quantity
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Quantity", "field_name":"quantity", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.uom:
            updated_lineitem_obj.uom = ''
        if not self.call_lineitem_obj.uom:
            self.call_lineitem_obj.uom = ''
        if updated_lineitem_obj.uom != self.call_lineitem_obj.uom:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.uom:
                old_value = self.call_lineitem_obj.uom
            new_value = 'Blank'
            if updated_lineitem_obj.uom:
                new_value = updated_lineitem_obj.uom
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"UOM", "field_name":"uom", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.part_num:
            updated_lineitem_obj.part_num = ''
        if not self.call_lineitem_obj.part_num:
            self.call_lineitem_obj.part_num = ''
        if updated_lineitem_obj.part_num != self.call_lineitem_obj.part_num:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.part_num:
                old_value = self.call_lineitem_obj.part_num
            new_value = 'Blank'
            if updated_lineitem_obj.part_num:
                new_value = updated_lineitem_obj.part_num
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Part Number", "field_name":"part_num", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.good_part_bar_code:
            updated_lineitem_obj.good_part_bar_code = ''
        if not self.call_lineitem_obj.good_part_bar_code:
            self.call_lineitem_obj.good_part_bar_code = ''
        if updated_lineitem_obj.good_part_bar_code != self.call_lineitem_obj.good_part_bar_code:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.good_part_bar_code:
                old_value = self.call_lineitem_obj.good_part_bar_code
            new_value = 'Blank'
            if updated_lineitem_obj.good_part_bar_code:
                new_value = updated_lineitem_obj.good_part_bar_code
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Good Part Barcode", "field_name":"good_part_bar_code", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.recd_way_bill_num:
            updated_lineitem_obj.recd_way_bill_num = ''
        if not self.call_lineitem_obj.recd_way_bill_num:
            self.call_lineitem_obj.recd_way_bill_num = ''
        if updated_lineitem_obj.recd_way_bill_num != self.call_lineitem_obj.recd_way_bill_num:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.recd_way_bill_num:
                old_value = self.call_lineitem_obj.recd_way_bill_num
            new_value = 'Blank'
            if updated_lineitem_obj.recd_way_bill_num:
                new_value = updated_lineitem_obj.recd_way_bill_num
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Received Way Bill Number", "field_name":"recd_way_bill_num", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.warehouse_ref_way_bill_num:
            updated_lineitem_obj.warehouse_ref_way_bill_num = ''
        if not self.call_lineitem_obj.warehouse_ref_way_bill_num:
            self.call_lineitem_obj.warehouse_ref_way_bill_num = ''
        if updated_lineitem_obj.warehouse_ref_way_bill_num != self.call_lineitem_obj.warehouse_ref_way_bill_num:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.warehouse_ref_way_bill_num:
                old_value = self.call_lineitem_obj.warehouse_ref_way_bill_num
            new_value = 'Blank'
            if updated_lineitem_obj.warehouse_ref_way_bill_num:
                new_value = updated_lineitem_obj.warehouse_ref_way_bill_num
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Warehouse Way Bill Number", "field_name":"warehouse_ref_way_bill_num", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.disposition_code_3pl:
            updated_lineitem_obj.disposition_code_3pl = ''
        if not self.call_lineitem_obj.disposition_code_3pl:
            self.call_lineitem_obj.disposition_code_3pl = ''
        if updated_lineitem_obj.disposition_code_3pl != self.call_lineitem_obj.disposition_code_3pl:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.disposition_code_3pl:
                old_value = self.call_lineitem_obj.disposition_code_3pl
            new_value = 'Blank'
            if updated_lineitem_obj.disposition_code_3pl:
                new_value = updated_lineitem_obj.disposition_code_3pl
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Disposition Code 3pl", "field_name":"disposition_code_3pl", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.defective_bar_code_num:
            updated_lineitem_obj.defective_bar_code_num = ''
        if not self.call_lineitem_obj.defective_bar_code_num:
            self.call_lineitem_obj.defective_bar_code_num = ''
        if updated_lineitem_obj.defective_bar_code_num != self.call_lineitem_obj.defective_bar_code_num:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.defective_bar_code_num:
                old_value = self.call_lineitem_obj.defective_bar_code_num
            new_value = 'Blank'
            if updated_lineitem_obj.defective_bar_code_num:
                new_value = updated_lineitem_obj.defective_bar_code_num
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Defective BarCode Number", "field_name":"defective_bar_code_num", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.returned_awb_num:
            updated_lineitem_obj.returned_awb_num = ''
        if not self.call_lineitem_obj.returned_awb_num:
            self.call_lineitem_obj.returned_awb_num = ''
        if updated_lineitem_obj.returned_awb_num != self.call_lineitem_obj.returned_awb_num:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.returned_awb_num:
                old_value = self.call_lineitem_obj.returned_awb_num
            new_value = 'Blank'
            if updated_lineitem_obj.returned_awb_num:
                new_value = updated_lineitem_obj.returned_awb_num
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Returned AWB Number", "field_name":"returned_awb_num", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.returned_dc_num:
            updated_lineitem_obj.returned_dc_num = ''
        if not self.call_lineitem_obj.returned_dc_num:
            self.call_lineitem_obj.returned_dc_num = ''
        if updated_lineitem_obj.returned_dc_num != self.call_lineitem_obj.returned_dc_num:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.returned_dc_num:
                old_value = self.call_lineitem_obj.returned_dc_num
            new_value = 'Blank'
            if updated_lineitem_obj.returned_dc_num:
                new_value = updated_lineitem_obj.returned_dc_num
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Returned DC Number", "field_name":"returned_dc_num", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.part_received_date:
            updated_lineitem_obj.part_received_date = ''
        if not self.call_lineitem_obj.part_received_date:
            self.call_lineitem_obj.part_received_date = ''
        if updated_lineitem_obj.part_received_date != self.call_lineitem_obj.part_received_date:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.part_received_date:
                old_value =  get_date_disp_value(self.call_lineitem_obj.part_received_date, self.request.session['SHORT_DATE_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            new_value = 'Blank'
            if updated_lineitem_obj.part_received_date:
                new_value = get_date_disp_value(updated_lineitem_obj.part_received_date, self.request.session['SHORT_DATE_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Part Received Date", "field_name":"part_received_date", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.returned_date:
            updated_lineitem_obj.returned_date = ''
        if not self.call_lineitem_obj.returned_date:
            self.call_lineitem_obj.returned_date = ''
        if updated_lineitem_obj.returned_date != self.call_lineitem_obj.returned_date:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.returned_date:
                old_value = get_date_disp_value(self.call_lineitem_obj.returned_date, self.request.session['SHORT_DATE_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            new_value = 'Blank'
            if updated_lineitem_obj.returned_date:
                new_value = get_date_disp_value(updated_lineitem_obj.returned_date, self.request.session['SHORT_DATE_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Returned Date", "field_name":"returned_date", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.returned_dc_date:
            updated_lineitem_obj.returned_dc_date = ''
        if not self.call_lineitem_obj.returned_dc_date:
            self.call_lineitem_obj.returned_dc_date = ''
        if updated_lineitem_obj.returned_dc_date != self.call_lineitem_obj.returned_dc_date:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.returned_dc_date:
                old_value = get_date_disp_value(self.call_lineitem_obj.returned_dc_date, self.request.session['SHORT_DATE_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            new_value = 'Blank'
            if updated_lineitem_obj.returned_dc_date:
                new_value = get_date_disp_value(updated_lineitem_obj.returned_dc_date, self.request.session['SHORT_DATE_FORMAT'], self.request.session['DEFAULT_TIME_ZONE'])
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Returned DC Date", "field_name":"returned_dc_date", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.part_received_courier_name:
            updated_lineitem_obj.part_received_courier_name = ''
        if not self.call_lineitem_obj.part_received_courier_name:
            self.call_lineitem_obj.part_received_courier_name = ''
        if updated_lineitem_obj.part_received_courier_name != self.call_lineitem_obj.part_received_courier_name:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.part_received_courier_name:
                old_value = self.call_lineitem_obj.part_received_courier_name
            new_value = 'Blank'
            if updated_lineitem_obj.part_received_courier_name:
                new_value = updated_lineitem_obj.part_received_courier_name
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Part Received Courier Name", "field_name":"part_received_courier_name", "old_value":old_value, "new_value":new_value})
        if not updated_lineitem_obj.shipment_details:
            updated_lineitem_obj.shipment_details = ''
        if not self.call_lineitem_obj.shipment_details:
            self.call_lineitem_obj.shipment_details = ''
        if updated_lineitem_obj.shipment_details != self.call_lineitem_obj.shipment_details:
            make_audit_entry = True
            old_value = 'Blank'
            if self.call_lineitem_obj.shipment_details:
                old_value = self.call_lineitem_obj.shipment_details
            new_value = 'Blank'
            if updated_lineitem_obj.shipment_details:
                new_value = updated_lineitem_obj.shipment_details
            audit_json.append({"table_name":"TicketLineItem", "pk":updated_lineitem_obj.pk, "display_name":"Shipment Details", "field_name":"shipment_details", "old_value":old_value, "new_value":new_value})
        if make_audit_entry:
            change_audit = TicketChangesAudit(ticket = updated_lineitem_obj.ticket, audit_json = json.dumps(audit_json), updated_by = updating_user, updated_time = timezone.now())
            change_audit.save()
        return reverse('administrations:list_call_line_items', kwargs={'ticket_id':updated_lineitem_obj.ticket.pk})
    

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateCallLineItem(AdminCreateView):
    model = TicketLineItem
    form_class = CreateCallLineItemsForm
    template_name = 'create_call_line_item.html'
    success_message = 'Line item created sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(CreateCallLineItem,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        category_list = LineItemCategory.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        line_item_status_list = LineItemStatus.objects.filter(line_item_category__tenant = admin_user.tenant, is_active = True).order_by('rank')
        line_item_dispositioncode_list = LineItemDispositionCode.objects.filter(line_item_category__tenant = admin_user.tenant, is_active = True).order_by('rank')
        category_status_map = {}
        category_disposition_map = {}
        category_fields_map = {}
        category_status_map[-1] = list(line_item_status_list)
        category_disposition_map[-1] = list(line_item_dispositioncode_list)
        for categoryobj in category_list:
            line_item_status_list = LineItemStatus.objects.filter(line_item_category = categoryobj, is_active = True).order_by('rank')
            line_item_dispositioncode_list = LineItemDispositionCode.objects.filter(line_item_category = categoryobj, is_active = True).order_by('rank')
            field_list = FieldLineItemCategoryMap.objects.filter(line_item_category = categoryobj)
            category_status_map[categoryobj.id] = list(line_item_status_list)
            category_disposition_map[categoryobj.id] = list(line_item_dispositioncode_list)
            category_fields_map[categoryobj.id] = list(field_list)
        context['category_status_map'] = category_status_map
        context['category_disposition_map'] = category_disposition_map
        context['category_fields_map'] = category_fields_map
        category_choices = []
        category_choices.append([-1, '--------------'])
        for category in category_list:
            category_choices.append([category.id, category.name])
        context['form'].fields['category'].choices =  category_choices
        reasoncode_fields_map = {}
        reasoncode_list = ReasonCode.objects.filter(call_status__tenant = admin_user.tenant, is_active = True)
        for reasoncode in reasoncode_list:
            field_list = FieldReasonCodeMap.objects.filter(reason_code = reasoncode)
            reasoncode_fields_map[reasoncode.id] = list(field_list)
        context['reasoncode_fields_map'] = reasoncode_fields_map
        protected_fields = []
        field_lineitem_list = FieldLineItemCategoryMap.objects.filter(tenant = admin_user.tenant)
        for field_lineitem in field_lineitem_list:
            access_field = field_lineitem.access_field
            if not access_field in protected_fields:
                protected_fields.append(access_field.field_id)
        context['protected_fields'] = protected_fields
        status_disposition_map = {}
        status_disposition_map[0] = line_item_dispositioncode_list
        status_choices = []
        status_choices.append([-1, '--------------'])
        for status in line_item_status_list:
            disposition_details = LineItemDispositionCode.objects.filter(line_item_status= category.id )
            status_disposition_map[status.id] = disposition_details
            status_choices.append([status.id, status.name])
        context['status_disposition_map'] = status_disposition_map
        context['form'].fields['status'].choices =  status_choices
        return context

    def form_valid(self, form):
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        form.instance.ticket = callobj
        return super(CreateCallLineItem,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Call Line Itme created sucessfully!'
        return super(CreateCallLineItem, self).post(request, args, kwargs)

    def get_success_url(self):
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        return reverse('administrations:list_call_line_items', kwargs={'ticket_id':callobj.pk})


@class_view_decorator(login_required)
class ListCallLineItems(AdminListView):
    model = TicketLineItem
    template_name = 'call_line_items_list.html'

    def get_context_data(self, **kwargs):
        context = super(ListCallLineItems,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        call_line_items_list = TicketLineItem.objects.filter(ticket = callobj).order_by('-line_id')
        context['call_line_items_list'] = call_line_items_list
        return context
    
    
@class_view_decorator(login_required)
class ListCallNotes(AdminListView):
    model = TicketNotes
    template_name = 'call_notes_list.html'

    def get_context_data(self, **kwargs):
        context = super(ListCallNotes,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        call_notes_list = TicketNotes.objects.filter(ticket = callobj).order_by('-notes_entered_time')
        context['call_notes_list'] = call_notes_list
        return context

    
@class_view_decorator(login_required)
class ListCallDocuments(AdminListView):
    model = TicketNotes
    template_name = 'call_documents_list.html'

    def get_context_data(self, **kwargs):
        context = super(ListCallDocuments,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        call_document_list = TicketDocument.objects.filter(ticket = callobj).order_by('-upload_time')
        context['call_document_list'] = call_document_list
        return context

@class_view_decorator(login_required)
class ListTicketChangesAudit(AdminListView):
    model = TicketChangesAudit
    template_name = 'call_changes_audit_list.html'

    def get_context_data(self, **kwargs):
        context = super(ListTicketChangesAudit,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        call_changes_audit_list = TicketChangesAudit.objects.filter(ticket = callobj).order_by('-updated_time')
        context['call_changes_audit_list'] = call_changes_audit_list
        return context

    
@class_view_decorator(login_required)
class ListTicketStatusTrack(AdminListView):
    model = TicketStatusTrack
    template_name = 'call_status_tracking_list.html'

    def get_context_data(self, **kwargs):
        context = super(ListTicketStatusTrack,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        call_status_track_list = TicketStatusTrack.objects.filter(ticket = callobj).order_by('-status_change_time')
        context['call_status_track_list'] = call_status_track_list
        return context


@class_view_decorator(login_required)    
class DisplayCallEngineerFeedbackDetails(AdminTemplateView):
    template_name = 'call_engineer_feedback_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallEngineerFeedbackDetails,self).get_context_data(**kwargs)
        call_engineer_feedback_obj = TicketClosureNotes.objects.get(pk = self.kwargs['pk'])
        context['call_engineer_feedback_obj'] = call_engineer_feedback_obj
        context['callobj'] = call_engineer_feedback_obj.ticket
        return context

@class_view_decorator(login_required)
class CreateCallEngineerFeedbackDetail(View):
    model = TicketClosureNotes
    success_message = 'Engineer feedback added sucessfully!'

    def get(self, request, *args, **kwargs):
        ticket_id = self.kwargs['ticket_id']
        callobj = CallTicket.objects.filter(pk = ticket_id).first()
        ticketobj = TicketClosureNotes.objects.filter(ticket = callobj).first()
        if not ticketobj:    
            ticketobj = TicketClosureNotes(ticket = callobj)
            ticketobj.save()
        return HttpResponseRedirect(reverse('administrations:edit_call_engineer_feedback_details', kwargs={'pk':ticketobj.pk}))


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallEngineerFeedbackDetails(AdminUpdateView):
    model = TicketClosureNotes
    form_class = EditCallEngineerFeedbackDetailForm
    template_name = 'edit_call_engineer_feedback_details.html'
    success_message = 'Engineer feedback updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(EditCallEngineerFeedbackDetails,self).get_context_data(**kwargs)
        call_engineer_feedback_obj = TicketClosureNotes.objects.get(pk = self.kwargs['pk'])
        callobj = call_engineer_feedback_obj.ticket
        context['callobj'] = callobj
        context['call_engineer_feedback_obj'] = call_engineer_feedback_obj
        return context

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call Notes created sucessfully!'
        return super(EditCallEngineerFeedbackDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:display_call_engineer_feedback_details', kwargs={'pk':self.kwargs['pk']})
    

def handle_uploaded_file(save_file, f):
    with open(save_file, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateCallDocumentDetails(AdminCreateView):
    model = TicketDocument
    form_class = CreateCallDocumentForm
    template_name = 'create_call_document.html'
    success_message = 'New doument created sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(CreateCallDocumentDetails,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        return context

    def get_form_kwargs(self):
        kw = super(CreateCallDocumentDetails, self).get_form_kwargs()
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        kw['callobj'] = callobj
        return kw

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        form.instance.notes_entered_by = admin_user
        form.instance.ticket = callobj
        imagefile = self.request.FILES.get('file', None)
        extension = find_file_extension(imagefile.name)
        name = find_filename_without_extension(imagefile.name)
        filename = remove_spl_char(name) + '_' + str(uuid.uuid4()) + '.' + extension
        handle_uploaded_file(settings.UPLOADS_DIR + '/' + filename, imagefile)
        form.instance.document_url = '/file/' + filename
        form.instance.uploaded_by = admin_user
        return super(CreateCallDocumentDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call Notes created sucessfully!'
        return super(CreateCallDocumentDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        return reverse('administrations:list_call_documents', kwargs={'ticket_id':callobj.pk})

    
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class EditCallDocumentDetails(AdminUpdateView):
    model = TicketDocument
    form_class = UpdateCallDocumentForm
    template_name = 'edit_call_document.html'
    success_message = 'Document details updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(EditCallDocumentDetails,self).get_context_data(**kwargs)
        call_document_obj = TicketDocument.objects.get(pk = self.kwargs['pk'])
        callobj = call_document_obj.ticket
        context['callobj'] = callobj
        context['call_document_obj'] = call_document_obj
        return context

    def get_form_kwargs(self):
        kw = super(EditCallDocumentDetails, self).get_form_kwargs()
        call_document_obj = TicketDocument.objects.get(pk = self.kwargs['pk'])
        kw['call_document_obj'] = call_document_obj
        return kw
    
    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        form.instance.notes_entered_by = admin_user
        imagefile = self.request.FILES.get('file', None)
        if imagefile:
            extension = find_file_extension(imagefile.name)
            name = find_filename_without_extension(imagefile.name)
            filename = remove_spl_char(name) + '_' + str(uuid.uuid4()) + '.' + extension
            handle_uploaded_file(settings.UPLOADS_DIR + '/' + filename, imagefile)
            form.instance.document_url = '/file/' + filename
        return super(EditCallDocumentDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Call Notes created sucessfully!'
        return super(EditCallDocumentDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        call_document_obj = TicketDocument.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:list_call_documents', kwargs={'ticket_id':call_document_obj.ticket.pk})
    
    
@class_view_decorator(login_required)
class ListCountry(AdminListView):
    model = Country
    template_name = 'list_country.html'

    def get(self, request, *args, **kwargs):
        return super(ListCountry, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayCountryDetails(AdminTemplateView):
    template_name = 'display_country_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCountryDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        country_details = Country.objects.get(pk = kwargs['pk'])
        self.country_details = country_details
        return super(DisplayCountryDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateCountry(AdminCreateView):
    model = Country
    form_class = CreateCountryForm
    template_name = 'create_country.html'
    success_message = 'New Country created successfully'

    def get_form_kwargs(self):
        kw = super(CreateCountry, self).get_form_kwargs()
        return kw

    def form_valid(self, form):
        return super(CreateCountry,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCountry, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Country created successfully'
        return reverse('administrations:list_country')

@class_view_decorator(login_required)
class UpdateCountryDetails(AdminUpdateView):
    model = Country
    form_class = UpdateCountryDetailForm
    template_name = 'update_country_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCountryDetails,self).get_context_data(**kwargs)
        countryObj = Country.objects.get(pk = self.kwargs['pk'])
        context['countryObj'] = countryObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCountryDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCountryDetails, self).get_form_kwargs()
        return kw

    def post(self, request, *args, **kwargs):
        countryObj = Country.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Country details sucessfully!'
        return super(UpdateCountryDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:display_country_details', kwargs={'pk':self.kwargs['pk']})


@class_view_decorator(login_required)
class ListState(AdminListView):
    model = State
    template_name = 'list_state.html'

    def get(self, request, *args, **kwargs):
        return super(ListState, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayStateDetails(AdminTemplateView):
    template_name = 'display_state_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayStateDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        state_details = State.objects.get(pk = kwargs['pk'])
        self.state_details = state_details
        return super(DisplayStateDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateState(AdminCreateView):
    model = State
    form_class = CreateStateForm
    template_name = 'create_state.html'
    success_message = 'New State created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateState,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        country_details = Country.objects.filter(is_active = True).order_by('name')
        country_choices = []
        for country in country_details:
            country_choices.append([country.id, country.name])
        context['form'].fields['country'].choices = country_choices
        return context

    def get_form_kwargs(self):
        kw = super(CreateState, self).get_form_kwargs()
        return kw

    def form_valid(self, form):
        return super(CreateState,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateState, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New State created successfully'
        return reverse('administrations:list_state')

@class_view_decorator(login_required)
class UpdateStateDetails(AdminUpdateView):
    model = State
    form_class = UpdateStateDetailForm
    template_name = 'update_state_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateStateDetails,self).get_context_data(**kwargs)
        stateObj = State.objects.get(pk = self.kwargs['pk'])
        context['stateObj'] = stateObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateStateDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateStateDetails, self).get_form_kwargs()
        return kw

    def post(self, request, *args, **kwargs):
        stateObj = State.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated State details sucessfully!'
        return super(UpdateStateDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:display_state_details', kwargs={'pk':self.kwargs['pk']})

@class_view_decorator(login_required)
class ListVendor(AdminListView):
    model = Vendor
    template_name = 'list_vendor.html'
    
    def get(self, request, *args, **kwargs):
        return super(ListVendor, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayVendorDetails(AdminTemplateView):
    template_name = 'display_vendor_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayVendorDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        vendor_details = Vendor.objects.get(pk = kwargs['pk'])
        self.vendor_details = vendor_details
        return super(DisplayVendorDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateVendor(AdminCreateView):
    model = Vendor
    form_class = CreateVendorForm
    template_name = 'create_vendor.html'
    success_message = 'New Vendor created successfully'

    def get_form_kwargs(self):
        kw = super(CreateVendor, self).get_form_kwargs()
        return kw

    def form_valid(self, form):
        return super(CreateVendor,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateVendor, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Vendor created successfully'
        return reverse('administrations:list_vendor')

@class_view_decorator(login_required)
class UpdateVendorDetails(AdminUpdateView):
    model = Vendor
    form_class = UpdateVendorDetailForm
    template_name = 'update_vendor_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateVendorDetails,self).get_context_data(**kwargs)
        vendorObj = Vendor.objects.get(pk = self.kwargs['pk'])
        context['vendorObj'] = vendorObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateVendorDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateVendorDetails, self).get_form_kwargs()
        return kw

    def post(self, request, *args, **kwargs):
        vendorObj = Vendor.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Vendor Details Sucessfully!'
        return super(UpdateVendorDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:display_vendor_details', kwargs={'pk':self.kwargs['pk']})

@class_view_decorator(login_required)
class ListRegion(AdminListView):
    model = Region
    template_name = 'list_region.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Region.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListRegion, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayRegionDetails(AdminTemplateView):
    template_name = 'display_region_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayRegionDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        region_details = Region.objects.get(pk = kwargs['pk'])
        self.region_details = region_details
        return super(DisplayRegionDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateRegion(AdminCreateView):
    model = Region
    form_class = CreateRegionForm
    template_name = 'create_region.html'
    success_message = 'New Region created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateRegion,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateRegion, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateRegion,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateRegion, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Region created successfully'
        return reverse('administrations:list_region')

@class_view_decorator(login_required)
class UpdateRegionDetails(AdminUpdateView):
    model = Region
    form_class = UpdateRegionDetailForm
    template_name = 'update_region_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateRegionDetails,self).get_context_data(**kwargs)
        regionObj = Region.objects.get(pk = self.kwargs['pk'])
        context['regionObj'] = regionObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateRegionDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateRegionDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        region_details = Region.objects.get(pk = self.kwargs['pk'])
        kw['region_details'] = region_details
        return kw

    def post(self, request, *args, **kwargs):
        regionObj = Region.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Region details sucessfully!'
        return super(UpdateRegionDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_region')

@class_view_decorator(login_required)
class ListWarrantyType(AdminListView):
    model = WarrantyType
    template_name = 'list_warranty_type.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = WarrantyType.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListWarrantyType, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayWarrantyTypeDetails(AdminTemplateView):
    template_name = 'display_warranty_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayWarrantyTypeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        warrantytype_details = WarrantyType.objects.get(pk = kwargs['pk'])
        self.warrantytype_details = warrantytype_details
        return super(DisplayWarrantyTypeDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateWarrantyType(AdminCreateView):
    model = WarrantyType
    form_class = CreateWarrantyTypeForm
    template_name = 'create_warranty_type.html'
    success_message = 'New Support Type created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateWarrantyType,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateWarrantyType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateWarrantyType,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateWarrantyType, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Support Type created successfully'
        return reverse('administrations:list_warranty_type')

@class_view_decorator(login_required)
class UpdateWarrantyTypeDetails(AdminUpdateView):
    model = WarrantyType
    form_class = UpdateWarrantyTypeDetailForm
    template_name = 'update_warranty_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateWarrantyTypeDetails,self).get_context_data(**kwargs)
        warrantytypeObj = WarrantyType.objects.get(pk = self.kwargs['pk'])
        context['warrantytypeObj'] = warrantytypeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateWarrantyTypeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateWarrantyTypeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        warrantytype_details = WarrantyType.objects.get(pk = self.kwargs['pk'])
        kw['warrantytype_details'] = warrantytype_details
        return kw

    def post(self, request, *args, **kwargs):
        warrantytypeObj = WarrantyType.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Support Type details sucessfully!'
        return super(UpdateWarrantyTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_warranty_type')

@class_view_decorator(login_required)
class ListCallType(AdminListView):
    model = CallType
    template_name = 'list_call_type.html'

    def get_context_data(self, **kwargs):
        context = super(ListCallType,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = CallType.objects.filter(tenant = admin_user.tenant, vendor = self.kwargs['vendor_id'])
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListCallType, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayCallTypeDetails(AdminTemplateView):
    template_name = 'display_call_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallTypeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        calltype_details = CallType.objects.get(pk = kwargs['pk'])
        self.calltype_details = calltype_details
        return super(DisplayCallTypeDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateCallType(AdminCreateView):
    model = CallType
    form_class = CreateCallTypeForm
    template_name = 'create_call_type.html'
    success_message = 'New Call Type created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateCallType,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateCallType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor_id'] = self.kwargs['vendor_id']
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateCallType,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCallType, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Call Type created successfully'
        return reverse('administrations:list_call_type', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateCallTypeDetails(AdminUpdateView):
    model = CallType
    form_class = UpdateCallTypeDetailForm
    template_name = 'update_call_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCallTypeDetails,self).get_context_data(**kwargs)
        calltypeObj = CallType.objects.get(pk = self.kwargs['pk'])
        context['calltypeObj'] = calltypeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCallTypeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCallTypeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        calltype_details = CallType.objects.get(pk = self.kwargs['pk'])
        kw['calltype_details'] = calltype_details
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        calltype_details = CallType.objects.get(pk = self.kwargs['pk'])
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = calltype_details.vendor.pk)
        return super(UpdateCallTypeDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        calltypeObj = CallType.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Call Type details sucessfully!'
        return super(UpdateCallTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        calltype_details = CallType.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:list_call_type', kwargs={'vendor_id':calltype_details.vendor.pk})

@class_view_decorator(login_required)
class ListTicketType(AdminListView):
    model = TicketType
    template_name = 'list_ticket_type.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = TicketType.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListTicketType, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayTicketTypeDetails(AdminTemplateView):
    template_name = 'display_ticket_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayTicketTypeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        tickettype_details = TicketType.objects.get(pk = kwargs['pk'])
        self.tickettype_details = tickettype_details
        return super(DisplayTicketTypeDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateTicketType(AdminCreateView):
    model = TicketType
    form_class = CreateTicketTypeForm
    template_name = 'create_ticket_type.html'
    success_message = 'New Ticket Type created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateTicketType,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateTicketType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateTicketType,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateTicketType, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Ticket Type created successfully'
        return reverse('administrations:list_ticket_type')

@class_view_decorator(login_required)
class UpdateTicketTypeDetails(AdminUpdateView):
    model = TicketType
    form_class = UpdateTicketTypeDetailForm
    template_name = 'update_ticket_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateTicketTypeDetails,self).get_context_data(**kwargs)
        tickettypeObj = TicketType.objects.get(pk = self.kwargs['pk'])
        context['tickettypeObj'] = tickettypeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateTicketTypeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateTicketTypeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        tickettype_details = TicketType.objects.get(pk = self.kwargs['pk'])
        kw['tickettype_details'] = tickettype_details
        return kw

    def post(self, request, *args, **kwargs):
        tickettypeObj = TicketType.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Ticket Type details sucessfully!'
        return super(UpdateTicketTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_ticket_type')

@class_view_decorator(login_required)
class ListLineItemCategory(AdminListView):
    model = LineItemCategory
    template_name = 'list_lineitem_category.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = LineItemCategory.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListLineItemCategory, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayLineItemCategoryDetails(AdminTemplateView):
    template_name = 'display_lineitem_category_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayLineItemCategoryDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        lineitemcategory_details = LineItemCategory.objects.get(pk = kwargs['pk'])
        self.lineitemcategory_details = lineitemcategory_details
        return super(DisplayLineItemCategoryDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateLineItemCategory(AdminCreateView):
    model = LineItemCategory
    form_class = CreateLineItemCategoryForm
    template_name = 'create_lineitem_category.html'
    success_message = 'New LineItem Category created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateLineItemCategory,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateLineItemCategory, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateLineItemCategory,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateLineItemCategory, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New LineItem Category created successfully'
        return reverse('administrations:list_lineitem_category')

@class_view_decorator(login_required)
class UpdateLineItemCategoryDetails(AdminUpdateView):
    model = LineItemCategory
    form_class = UpdateLineItemCategoryDetailForm
    template_name = 'update_lineitem_category_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLineItemCategoryDetails,self).get_context_data(**kwargs)
        lineitemcategoryObj = LineItemCategory.objects.get(pk = self.kwargs['pk'])
        context['lineitemcategoryObj'] = lineitemcategoryObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateLineItemCategoryDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateLineItemCategoryDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        lineitemcategory_details = LineItemCategory.objects.get(pk = self.kwargs['pk'])
        kw['lineitemcategory_details'] = lineitemcategory_details
        return kw

    def post(self, request, *args, **kwargs):
        lineitemcategoryObj = LineItemCategory.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated LineItem Category details sucessfully!'
        return super(UpdateLineItemCategoryDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_lineitem_category')
    
@class_view_decorator(login_required)
class ListMachineType(AdminListView):
    model = MachineType
    template_name = 'list_machine_type.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = MachineType.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListMachineType, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayMachineTypeDetails(AdminTemplateView):
    template_name = 'display_machine_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayMachineTypeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        machinetype_details = MachineType.objects.get(pk = kwargs['pk'])
        self.machinetype_details = machinetype_details
        return super(DisplayMachineTypeDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateMachineType(AdminCreateView):
    model = MachineType
    form_class = CreateMachineTypeForm
    template_name = 'create_machine_type.html'

    def get_context_data(self, **kwargs):
        context = super(CreateMachineType,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateMachineType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateMachineType,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateMachineType, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Asset Type created successfully'
        return reverse('administrations:list_machine_type')

@class_view_decorator(login_required)
class UpdateMachineTypeDetails(AdminUpdateView):
    model = MachineType
    form_class = UpdateMachineTypeDetailForm
    template_name = 'update_machine_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateMachineTypeDetails,self).get_context_data(**kwargs)
        machinetypeObj = MachineType.objects.get(pk = self.kwargs['pk'])
        context['machinetypeObj'] = machinetypeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateMachineTypeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateMachineTypeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        machinetype_details = MachineType.objects.get(pk = self.kwargs['pk'])
        kw['machinetype_details'] = machinetype_details
        return kw

    def post(self, request, *args, **kwargs):
        machinetypeObj = MachineType.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Asset Type details sucessfully!'
        return super(UpdateMachineTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_machine_type')

@class_view_decorator(login_required)
class ListMachineMake(AdminListView):
    model = MachineMake
    template_name = 'list_machine_make.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = MachineMake.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListMachineMake, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayMachineMakeDetails(AdminTemplateView):
    template_name = 'display_machine_make_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayMachineMakeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        machinemake_details = MachineMake.objects.get(pk = kwargs['pk'])
        self.machinemake_details = machinemake_details
        return super(DisplayMachineMakeDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateMachineMake(AdminCreateView):
    model = MachineMake
    form_class = CreateMachineMakeForm
    template_name = 'create_machine_make.html'

    def get_context_data(self, **kwargs):
        context = super(CreateMachineMake,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateMachineMake, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateMachineMake,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateMachineMake, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Asset Make created successfully'
        return reverse('administrations:list_machine_make')

@class_view_decorator(login_required)
class UpdateMachineMakeDetails(AdminUpdateView):
    model = MachineMake
    form_class = UpdateMachineMakeDetailForm
    template_name = 'update_machine_make_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateMachineMakeDetails,self).get_context_data(**kwargs)
        machinemakeObj = MachineMake.objects.get(pk = self.kwargs['pk'])
        context['machinemakeObj'] = machinemakeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateMachineMakeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateMachineMakeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        machinemake_details = MachineMake.objects.get(pk = self.kwargs['pk'])
        kw['machinemake_details'] = machinemake_details
        return kw

    def post(self, request, *args, **kwargs):
        machinemakeObj = MachineMake.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Asset Make details sucessfully!'
        return super(UpdateMachineMakeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_machine_make')

@class_view_decorator(login_required)
class ListAdminRole(AdminListView):
    model = AdminRole
    template_name = 'list_admin_role.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = AdminRole.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListAdminRole, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayAdminRoleDetails(AdminTemplateView):
    template_name = 'display_admin_role_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayAdminRoleDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        adminrole_details = AdminRole.objects.get(pk = kwargs['pk'])
        self.adminrole_details = adminrole_details
        return super(DisplayAdminRoleDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateAdminRole(AdminCreateView):
    model = AdminRole
    form_class = CreateAdminRoleForm
    template_name = 'create_admin_role.html'
    success_message = 'New Admin Role created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateAdminRole,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateAdminRole, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateAdminRole,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateAdminRole, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Admin Role created successfully'
        return reverse('administrations:list_admin_role')

@class_view_decorator(login_required)
class UpdateAdminRoleDetails(AdminUpdateView):
    model = AdminRole
    form_class = UpdateAdminRoleDetailForm
    template_name = 'update_admin_role_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateAdminRoleDetails,self).get_context_data(**kwargs)
        adminroleObj = AdminRole.objects.get(pk = self.kwargs['pk'])
        context['adminroleObj'] = adminroleObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateAdminRoleDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateAdminRoleDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        adminrole_details = AdminRole.objects.get(pk = self.kwargs['pk'])
        kw['adminrole_details'] = adminrole_details
        return kw

    def post(self, request, *args, **kwargs):
        adminroleObj = AdminRole.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Admin Role details sucessfully!'
        return super(UpdateAdminRoleDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_admin_role')

@class_view_decorator(login_required)
class ListLocation(AdminListView):
    model = Location
    template_name = 'list_location.html'
    
    def get_context_data(self, **kwargs):
        context = super(ListLocation,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Location.objects.filter(branch__tenant = admin_user.tenant, branch__vendor = self.kwargs['vendor_id'])
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListLocation, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateLocation(AdminCreateView):
    model = Location
    form_class = CreateLocationForm
    template_name = 'create_location.html'

    def get_context_data(self, **kwargs):
        context = super(CreateLocation,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        branch_details = Branch.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], is_active = True).order_by('name')
        location_choices = []
        location_choices.append([-1, '--------------'])
        for branch in branch_details:
            location_choices.append([branch.id, str(branch.name) + "-" +str(branch.vendor)])
        context['form'].fields['branch'].choices =  location_choices
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get_form_kwargs(self):
        kw = super(CreateLocation, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor_id'] = self.kwargs['vendor_id']
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        return super(CreateLocation,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateLocation, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Location created successfully'
        return reverse('administrations:list_location', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class DisplayLocationDetails(AdminTemplateView):
    template_name = 'display_location_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayLocationDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        location_details = Location.objects.get(pk = self.kwargs['pk'])
        self.location_details = location_details
        return super(DisplayLocationDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateLocationDetails(AdminUpdateView):
    model = Location
    form_class = UpdateLocationDetailForm
    template_name = 'update_location_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLocationDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        branch_details = Branch.objects.filter(tenant = admin_user.tenant, vendor = self.kwargs['vendor_id'], is_active = True).order_by('name')
        locationObj = Location.objects.get(pk = self.kwargs['pk'])
        location_choices = []
        location_choices.append([-1, '--------------'])
        for branch in branch_details:
            location_choices.append([branch.id, str(branch.name) + "-" +str(branch.vendor)])
        context['form'].fields['branch'].choices =  location_choices
        context['locationObj'] = locationObj
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateLocationDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateLocationDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        location_details = Location.objects.get(pk = self.kwargs['pk'])
        kw['tenant'] = admin_user.tenant
        kw['location_details'] = location_details
        kw['vendor_id'] = self.kwargs['vendor_id']
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Location details sucessfully!'
        return super(UpdateLocationDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_location', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class ListDesignation(AdminListView):
    model = Designation
    template_name = 'list_designation.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Designation.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListDesignation, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayDesignationDetails(AdminTemplateView):
    template_name = 'display_designation_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayDesignationDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        designation_details = Designation.objects.get(pk = kwargs['pk'])
        self.designation_details = designation_details
        return super(DisplayDesignationDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateDesignation(AdminCreateView):
    model = Designation
    form_class = CreateDesignationForm
    template_name = 'create_designation.html'

    def get_context_data(self, **kwargs):
        context = super(CreateDesignation,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateDesignation, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateDesignation,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateDesignation, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Designation created successfully'
        return reverse('administrations:list_designation')

@class_view_decorator(login_required)
class UpdateDesignationDetails(AdminUpdateView):
    model = Designation
    form_class = UpdateDesignationDetailForm
    template_name = 'update_designation_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateDesignationDetails,self).get_context_data(**kwargs)
        designationObj = Designation.objects.get(pk = self.kwargs['pk'])
        context['designationObj'] = designationObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateDesignationDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateDesignationDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        designation_details = Designation.objects.get(pk = self.kwargs['pk'])
        kw['designation_details'] = designation_details
        return kw

    def post(self, request, *args, **kwargs):
        designationObj = Designation.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Designation details sucessfully!'
        return super(UpdateDesignationDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_designation')

@class_view_decorator(login_required)
class ListCallStatus(AdminListView):
    model = CallStatus
    template_name = 'list_call_status.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = CallStatus.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListCallStatus, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayCallStatusDetails(AdminTemplateView):
    template_name = 'display_call_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallStatusDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        callstatus_details = CallStatus.objects.get(pk = kwargs['pk'])
        self.callstatus_details = callstatus_details
        return super(DisplayCallStatusDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateCallStatus(AdminCreateView):
    model = CallStatus
    form_class = CreateCallStatusForm
    template_name = 'create_call_status.html'

    def get_context_data(self, **kwargs):
        context = super(CreateCallStatus,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateCallStatus, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateCallStatus,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCallStatus, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Call Status created successfully'
        return reverse('administrations:list_call_status')

@class_view_decorator(login_required)
class UpdateCallStatusDetails(AdminUpdateView):
    model = CallStatus
    form_class = UpdateCallStatusDetailForm
    template_name = 'update_call_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCallStatusDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        callstatusObj = CallStatus.objects.get(pk = self.kwargs['pk'])
        context['callstatusObj'] = callstatusObj
        callstatus_details = CallStatus.objects.filter(tenant = admin_user.tenant, is_active = True).exclude(id__in = self.kwargs['pk'])
        context['form'].fields['transition_statuses'].queryset  = callstatus_details
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCallStatusDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCallStatusDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        callstatus_details = CallStatus.objects.get(pk = self.kwargs['pk'])
        kw['callstatus_details'] = callstatus_details
        return kw

    def post(self, request, *args, **kwargs):
        callstatusObj = CallStatus.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Call Status details sucessfully!'
        return super(UpdateCallStatusDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_call_status')

@class_view_decorator(login_required)
class ListReasonCode(AdminListView):
    model = ReasonCode
    template_name = 'list_reason_code.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = ReasonCode.objects.filter(call_status__tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListReasonCode, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateReasonCode(AdminCreateView):
    model = ReasonCode
    form_class = CreateReasonCodeForm
    template_name = 'create_reason_code.html'

    def get_context_data(self, **kwargs):
        context = super(CreateReasonCode,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        call_status_details = CallStatus.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        reason_code_map = {}
        for call_status in call_status_details:
            reasoncode_details = ReasonCode.objects.filter(call_status__tenant = adminobj.tenant, is_active = True, call_status_id = call_status)
            reason_code_map[call_status.id] = reasoncode_details
        context['form'].fields['call_status'].queryset =  call_status_details
        context['reason_code_map'] = reason_code_map
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateReasonCode, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        return super(CreateReasonCode,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateReasonCode, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Reason Code created successfully'
        return reverse('administrations:list_reason_code')

@class_view_decorator(login_required)
class DisplayReasonCodeDetails(AdminTemplateView):
    template_name = 'display_reason_code_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayReasonCodeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        reasoncode_details = ReasonCode.objects.get(pk = self.kwargs['pk'])
        self.reasoncode_details = reasoncode_details
        return super(DisplayReasonCodeDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateReasonCodeDetails(AdminUpdateView):
    model = ReasonCode
    form_class = UpdateReasonCodeDetailForm
    template_name = 'update_reason_code_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateReasonCodeDetails,self).get_context_data(**kwargs)
        reason_code_map = {}
        reason_code_map['0'] = []
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        reasoncodeObj = ReasonCode.objects.get(pk = self.kwargs['pk'])
        call_status_details = CallStatus.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        for call_status in call_status_details:
            reasoncode_details = ReasonCode.objects.filter(call_status__tenant = adminobj.tenant, is_active = True, call_status_id = call_status)
            reason_code_map[call_status.id] = reasoncode_details
        context['reason_code_map'] = reason_code_map 
        context['form'].fields['call_status'].queryset =  call_status_details
        context['reasoncodeObj'] = reasoncodeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateReasonCodeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateReasonCodeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        reasoncode_details = ReasonCode.objects.get(pk = self.kwargs['pk'])
        kw['reasoncode_details'] = reasoncode_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Reason Code details sucessfully!'
        return super(UpdateReasonCodeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_reason_code')

@class_view_decorator(login_required)
class ListLineItemStatus(AdminListView):
    model = LineItemStatus
    template_name = 'list_lineitem_status.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = LineItemStatus.objects.filter(line_item_category__tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListLineItemStatus, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateLineItemStatus(AdminCreateView):
    model = LineItemStatus
    form_class = CreateLineItemStatusForm
    template_name = 'create_lineitem_status.html'

    def get_context_data(self, **kwargs):
        context = super(CreateLineItemStatus,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        line_item_category_details = LineItemCategory.objects.filter(is_active = True).order_by('name')
        context['form'].fields['line_item_category'].queryset =  line_item_category_details
        return context

    def get_form_kwargs(self):
        kw = super(CreateLineItemStatus, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        return super(CreateLineItemStatus,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateLineItemStatus, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New LineItem Status created successfully'
        return reverse('administrations:list_lineitem_status')

@class_view_decorator(login_required)
class DisplayLineItemStatusDetails(AdminTemplateView):
    template_name = 'display_lineitem_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayLineItemStatusDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        lineitemstatus_details = LineItemStatus.objects.get(pk = self.kwargs['pk'])
        self.lineitemstatus_details = lineitemstatus_details
        return super(DisplayLineItemStatusDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateLineItemStatusDetails(AdminUpdateView):
    model = LineItemStatus
    form_class = UpdateLineItemStatusDetailForm
    template_name = 'update_lineitem_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLineItemStatusDetails,self).get_context_data(**kwargs)
        lineitemstatusObj = LineItemStatus.objects.get(pk = self.kwargs['pk'])
        context['lineitemstatusObj'] = lineitemstatusObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateLineItemStatusDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateLineItemStatusDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        lineitemstatus_details = LineItemStatus.objects.get(pk = self.kwargs['pk'])
        kw['lineitemstatus_details'] = lineitemstatus_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated LineItem Status details sucessfully!'
        return super(UpdateLineItemStatusDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_lineitem_status')

@class_view_decorator(login_required)
class ListLineItemDispositionCode(AdminListView):
    model = LineItemDispositionCode
    template_name = 'list_lineitem_disposition_code.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = LineItemDispositionCode.objects.filter(line_item_category__tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListLineItemDispositionCode, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateLineItemDispositionCode(AdminCreateView):
    model = LineItemDispositionCode
    form_class = CreateLineItemDispositionCodeForm
    template_name = 'create_lineitem_disposition_code.html'

    def get_context_data(self, **kwargs):
        context = super(CreateLineItemDispositionCode,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        line_item_category_details = LineItemCategory.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        line_item_status_details = LineItemStatus.objects.filter( is_active = True).order_by('name')
        item_status_map = {}
        line_item_category_choices = []
        line_item_category_choices.append(['','---------'])
        item_status_map[0] = line_item_status_details
        for category in line_item_category_details:
            status_details = LineItemStatus.objects.filter(line_item_category= category.id )
            if len(status_details) > 0 :  
                line_item_category_choices.append([category.id, category.name])
                item_status_map[category.id] = status_details
        context['item_status_map'] = item_status_map
        context['form'].fields['line_item_category'].choices =  line_item_category_choices
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateLineItemDispositionCode, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        return super(CreateLineItemDispositionCode,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateLineItemDispositionCode, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Line Item Disposition Code created successfully'
        return reverse('administrations:list_lineitem_disposition_code')

@class_view_decorator(login_required)
class DisplayLineItemDispositionCodeDetails(AdminTemplateView):
    template_name = 'display_lineitem_disposition_code_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayLineItemDispositionCodeDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        lineitemdispositioncode_details = LineItemDispositionCode.objects.get(pk = self.kwargs['pk'])
        self.lineitemdispositioncode_details = lineitemdispositioncode_details
        return super(DisplayLineItemDispositionCodeDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateLineItemDispositionCodeDetails(AdminUpdateView):
    model = LineItemDispositionCode
    form_class = UpdateLineItemDispositionCodeDetailForm
    template_name = 'update_lineitem_disposition_code_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLineItemDispositionCodeDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        lineitemdispositioncodeObj = LineItemDispositionCode.objects.get(pk = self.kwargs['pk'])
        line_item_category_details = LineItemCategory.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        line_item_status_details = LineItemStatus.objects.filter( is_active = True).order_by('name')
        item_status_map = {}
        line_item_category_choices = []
        line_item_category_choices.append(['','---------'])
        item_status_map[0] = line_item_status_details
        for category in line_item_category_details:
            status_details = LineItemStatus.objects.filter(line_item_category= category.id )
            if len(status_details) > 0 :  
                line_item_category_choices.append([category.id, category.name])
                item_status_map[category.id] = status_details
        context['item_status_map'] = item_status_map
        context['form'].fields['line_item_category'].choices =  line_item_category_choices
        context['lineitemdispositioncodeObj'] = lineitemdispositioncodeObj
        return context
    
    def get(self, request, *args, **kwargs):
        return super(UpdateLineItemDispositionCodeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateLineItemDispositionCodeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        lineitemdispositioncode_details = LineItemDispositionCode.objects.get(pk = self.kwargs['pk'])
        kw['lineitemdispositioncode_details'] = lineitemdispositioncode_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Line Item Disposition Code details sucessfully!'
        return super(UpdateLineItemDispositionCodeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_lineitem_disposition_code')

@class_view_decorator(login_required)
class ListUserStatus(AdminListView):
    model = UserStatus
    template_name = 'list_user_status.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = UserStatus.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListUserStatus, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayUserStatusDetails(AdminTemplateView):
    template_name = 'display_user_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayUserStatusDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        userstatus_details = UserStatus.objects.get(pk = kwargs['pk'])
        self.userstatus_details = userstatus_details
        return super(DisplayUserStatusDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateUserStatus(AdminCreateView):
    model = UserStatus
    form_class = CreateUserStatusForm
    template_name = 'create_user_status.html'

    def get_context_data(self, **kwargs):
        context = super(CreateUserStatus,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateUserStatus, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateUserStatus,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateUserStatus, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Employee Status created successfully'
        return reverse('administrations:list_user_status')

@class_view_decorator(login_required)
class UpdateUserStatusDetails(AdminUpdateView):
    model = UserStatus
    form_class = UpdateUserStatusDetailForm
    template_name = 'update_user_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateUserStatusDetails,self).get_context_data(**kwargs)
        userstatusObj = UserStatus.objects.get(pk = self.kwargs['pk'])
        context['userstatusObj'] = userstatusObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateUserStatusDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateUserStatusDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        userstatus_details = UserStatus.objects.get(pk = self.kwargs['pk'])
        kw['userstatus_details'] = userstatus_details
        kw['tenant'] = admin_user.tenant
        return kw

    def post(self, request, *args, **kwargs):
        userstatusObj = UserStatus.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Employee Status details sucessfully!'
        return super(UpdateUserStatusDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_user_status')

@class_view_decorator(login_required)
class ListCustomerStatus(AdminListView):
    model = CustomerStatus
    template_name = 'list_customer_status.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = CustomerStatus.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListCustomerStatus, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayCustomerStatusDetails(AdminTemplateView):
    template_name = 'display_customer_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCustomerStatusDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        customerstatus_details = CustomerStatus.objects.get(pk = kwargs['pk'])
        self.customerstatus_details = customerstatus_details
        return super(DisplayCustomerStatusDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateCustomerStatus(AdminCreateView):
    model = CustomerStatus
    form_class = CreateCustomerStatusForm
    template_name = 'create_customer_status.html'

    def get_context_data(self, **kwargs):
        context = super(CreateCustomerStatus,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateCustomerStatus, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateCustomerStatus,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCustomerStatus, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Customer Status created successfully'
        return reverse('administrations:list_customer_status')

@class_view_decorator(login_required)
class UpdateCustomerStatusDetails(AdminUpdateView):
    model = CustomerStatus
    form_class = UpdateCustomerStatusDetailForm
    template_name = 'update_customer_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCustomerStatusDetails,self).get_context_data(**kwargs)
        customerstatusObj = CustomerStatus.objects.get(pk = self.kwargs['pk'])
        context['customerstatusObj'] = customerstatusObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCustomerStatusDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCustomerStatusDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        customerstatus_details = CustomerStatus.objects.get(pk = self.kwargs['pk'])
        kw['tenant'] = admin_user.tenant
        kw['customerstatus_details'] = customerstatus_details
        return kw

    def post(self, request, *args, **kwargs):
        customerstatusObj = CustomerStatus.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Customer Status details sucessfully!'
        return super(UpdateCustomerStatusDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_customer_status')

@class_view_decorator(login_required)
class ListAssetStatus(AdminListView):
    model = AssetStatus
    template_name = 'list_asset_status.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = AssetStatus.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListAssetStatus, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayAssetStatusDetails(AdminTemplateView):
    template_name = 'display_asset_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayAssetStatusDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        assetstatus_details = AssetStatus.objects.get(pk = kwargs['pk'])
        self.assetstatus_details = assetstatus_details
        return super(DisplayAssetStatusDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateAssetStatus(AdminCreateView):
    model = AssetStatus
    form_class = CreateAssetStatusForm
    template_name = 'create_asset_status.html'

    def get_context_data(self, **kwargs):
        context = super(CreateAssetStatus,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateAssetStatus, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateAssetStatus,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateAssetStatus, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Asset Status created successfully'
        return reverse('administrations:list_asset_status')

@class_view_decorator(login_required)
class UpdateAssetStatusDetails(AdminUpdateView):
    model = AssetStatus
    form_class = UpdateAssetStatusDetailForm
    template_name = 'update_asset_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateAssetStatusDetails,self).get_context_data(**kwargs)
        assetstatusObj = AssetStatus.objects.get(pk = self.kwargs['pk'])
        context['assetstatusObj'] = assetstatusObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateAssetStatusDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateAssetStatusDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        assetstatus_details = AssetStatus.objects.get(pk = self.kwargs['pk'])
        kw['tenant'] = admin_user.tenant
        kw['assetstatus_details'] = assetstatus_details
        return kw

    def post(self, request, *args, **kwargs):
        assetstatusObj = AssetStatus.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Asset Status details sucessfully!'
        return super(UpdateAssetStatusDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_asset_status')

@class_view_decorator(login_required)
class ListMachineModel(AdminListView):
    model = MachineModel
    template_name = 'list_machine_model.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = MachineModel.objects.filter(machine_type__tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListMachineModel, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateMachineModel(AdminCreateView):
    model = MachineModel
    form_class = CreateMachineModelForm
    template_name = 'create_machine_model.html'

    def get_context_data(self, **kwargs):
        context = super(CreateMachineModel,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        machinetype_details = MachineType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        machinemake_details = MachineMake.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['machine_type'].queryset =  machinetype_details
        context['form'].fields['machine_make'].queryset =  machinemake_details
        return context

    def get_form_kwargs(self):
        kw = super(CreateMachineModel, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        return super(CreateMachineModel,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateMachineModel, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Asset Model created successfully'
        return reverse('administrations:list_machine_model')

@class_view_decorator(login_required)
class DisplayMachineModelDetails(AdminTemplateView):
    template_name = 'display_machine_model_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayMachineModelDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        machinemodel_details = MachineModel.objects.get(pk = self.kwargs['pk'])
        self.machinemodel_details = machinemodel_details
        return super(DisplayMachineModelDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateMachineModelDetails(AdminUpdateView):
    model = MachineModel
    form_class = UpdateMachineModelDetailForm
    template_name = 'update_machine_model_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateMachineModelDetails,self).get_context_data(**kwargs)
        machinemodelObj = MachineModel.objects.get(pk = self.kwargs['pk'])
        context['machinemodelObj'] = machinemodelObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateMachineModelDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateMachineModelDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        machinemodel_details = MachineModel.objects.get(pk = self.kwargs['pk'])
        kw['machinemodel_details'] = machinemodel_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Asset Model details sucessfully!'
        return super(UpdateMachineModelDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_machine_model')

@class_view_decorator(login_required)
class ListProjects(AdminListView):
    model = Project
    template_name = 'list_projects.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Project.objects.filter(branch__tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListProjects, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateProject(AdminCreateView):
    model = Project
    form_class = CreateProjectForm
    template_name = 'create_project.html'
    success_message = 'New Project created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateProject,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        branch_details = Branch.objects.filter(is_active = True).order_by('name')
        context['form'].fields['branch'].queryset =  branch_details
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateProject, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        return super(CreateProject,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateProject, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Project created successfully'
        return reverse('administrations:list_projects')

@class_view_decorator(login_required)
class DisplayProjectDetails(AdminTemplateView):
    template_name = 'display_project_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayProjectDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        project_details = Project.objects.get(pk = self.kwargs['pk'])
        self.project_details = project_details
        return super(DisplayProjectDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateProjectDetails(AdminUpdateView):
    model = Project
    form_class = UpdateProjectDetailForm
    template_name = 'update_project_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateProjectDetails,self).get_context_data(**kwargs)
        projectObj = Project.objects.get(pk = self.kwargs['pk'])
        context['projectObj'] = projectObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateProjectDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateProjectDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        project_details = Project.objects.get(pk = self.kwargs['pk'])
        kw['project_details'] = project_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Project details sucessfully!'
        return super(UpdateProjectDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_projects')

@class_view_decorator(login_required)
class ListAdministrators(AdminListView):
    model = Administrator
    template_name = 'list_administrators.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        if adminobj.is_super_user:
            queryset = Administrator.objects.filter(tenant = adminobj.tenant, is_active = True)
        else:    
            queryset = Administrator.objects.filter(tenant = adminobj.tenant, is_active = True, is_super_user = False)
        queryset = queryset.exclude(pk = adminobj)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListAdministrators, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateAdministrator(AdminCreateView):
    model = Administrator
    form_class = CreateAdministratorForm
    template_name = 'create_administrator.html'
    success_message = 'New Administrator created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateAdministrator,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        designation_list = Designation.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        branchObj = Branch.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        status_list = UserStatus.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        roles_list = AdminRole.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        vendor_branch_map = {}
        vendor_details = Vendor.objects.filter(is_active = True).order_by('name')
        vendor_list = self.request.session.get('user_vendor_list')
        if vendor_list:
            vendor_details = vendor_details.filter(pk__in = vendor_list)
            branchObj = branchObj.filter(vendor__in = vendor_list)
            if len(vendor_details) == 1:
                context['form'].fields['vendors'].initial = vendor_details
            context['form'].fields['vendors'].queryset = vendor_details
        vendor_branch_map = {}
        vendor_branch_map['0'] = branchObj
        for vendor in vendor_details:
            branch_details = branchObj.filter(vendor = vendor)
            vendor_branch_map[vendor.id] = branch_details
        customer_list = Customer.objects.filter(branch__tenant = adminobj.tenant)
        customer_choices = []
        for customer in customer_list:
            if customer.is_customer_complete_one():
                customer_choices.append([customer.id, customer.get_customer_branch_value()])
        status_choices = []
        status_choices.append([-1, '--------------'])
        for status in status_list:
            status_choices.append([status.id, status.name])
        designation_choices = []
        designation_choices.append([-1, '--------------'])
        for designation in designation_list:
            designation_choices.append([designation.id, designation.name])
        roles_choices = []
        for roles in roles_list:
            roles_choices.append([roles.id, roles.name])
        context['form'].fields['access_customers'].choices =  customer_choices
        context['form'].fields['roles'].choices =  roles_choices
        context['form'].fields['status'].choices =  status_choices
        context['vendor_branch_map'] = vendor_branch_map
        #context['form'].fields['branch'].queryset =  branch_details
        context['form'].fields['designation'].choices =  designation_choices
        return context
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        entered_username = generate_username(form.instance.email)
        user_name =  entered_username
        form.instance.username = user_name
        form.instance.password = 'pbkdf2_sha256$20000$KzPiNnhdCFhF$KxUw8u3uW3bRFG6J4i5vWZErqmmypMTFQYi4s0PmffE='
        form.instance.tenant = adminobj.tenant
        form.instance.join_date = datetime.now().date()
        url_id = uuid.uuid4().hex
        form.instance.password_reset_uuid = url_id
        form.instance.pssword_reset_uuid_create_time = timezone.now()
        form.instance.mobile_number = validate_mobile_countryCode(self.request.POST.get('mobile_number'))
        return super(CreateAdministrator,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateAdministrator, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateAdministrator, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Administrator created successfully'
        
        administrator = self.object
        if self.request.config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'False':
            engineerobj = Engineer(pk = administrator.pk)
            engineerobj.save_base(raw=True)
        try: 
            generate_invite_url = self.request.build_absolute_uri(reverse('change_password', kwargs={'url_id': administrator.password_reset_uuid}))
            from_email = settings.EMAIL_FROM
            if self.request.config_map['FROM_EMAIL']:
                from_email = self.request.config_map['FROM_EMAIL']               
            if self.request.config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'True':
                email_subject = 'Welcome to Hi Tech'
                email_body = '<html><body>Dear ' + str(administrator.first_name) + ',<br/><br/>Account has been created for you to access the Hi Tech Call Management System. Please click the following link to set your password.<br/><br/><a href="' + str(generate_invite_url) + '">' + str(generate_invite_url) + '</a>.<br/><br/>After setting your password, please login with username: <b>' + str(administrator.email) + '</b><br/><br/>Thank you,<br/>Hi Tech Team</body></html>'
            else:
                email_subject = 'Welcome to Cipla'
                email_body = '<html><body>Dear ' + str(administrator.first_name) + ',<br/><br/>Account has been created for you to access the Cipla Call Management System. Please click the following link to set your password.<br/><br/><a href="' + str(generate_invite_url) + '">' + str(generate_invite_url) + '</a>.<br/><br/>After setting your password, please login with username: <b>' + str(administrator.email) + '</b><br/><br/>Thank you,<br/>Cipla Team</body></html>'
            send_email_message(from_email, [administrator.email], None, None, email_subject, email_body)
              
        except Exception as e:
            logger.exception("Unable to send the invite SMS")
            logger.exception(e)
            self.success_message += '. Unable to send welcome SMS'
        return reverse('administrations:list_administrators')

@class_view_decorator(login_required)
class DisplayAdministratorDetails(AdminTemplateView):
    template_name = 'display_administrator_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayAdministratorDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        administrator_details = Administrator.objects.get(pk = self.kwargs['pk'])
        self.administrator_details = administrator_details
        return super(DisplayAdministratorDetails, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class UpdateAdministratorDetails(AdminUpdateView):
    model = Administrator
    form_class = UpdateAdministratorDetailForm
    template_name = 'update_administrator_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateAdministratorDetails,self).get_context_data(**kwargs)
        administratorObj = Administrator.objects.get(pk = self.kwargs['pk'])
        context['administratorObj'] = administratorObj
        branchObj = Branch.objects.filter(tenant = administratorObj.tenant, is_active = True).order_by('name')
        designation_list = Designation.objects.filter(tenant = administratorObj.tenant, is_active = True).order_by('name')
        status_list = UserStatus.objects.filter(tenant = administratorObj.tenant, is_active = True).order_by('name')
        roles_list = AdminRole.objects.filter(tenant = administratorObj.tenant, is_active = True).order_by('name')
        vendor_list = self.request.session.get('user_vendor_list') 
        vendor_details = Vendor.objects.filter(is_active = True).order_by('name')
        if vendor_list:
            vendor_details = vendor_details.filter(pk__in = vendor_list)
            branchObj = branchObj.filter(vendor__in = vendor_list)
            if len(vendor_details) == 1:
                context['form'].fields['vendors'].initial = vendor_details
            context['form'].fields['vendors'].queryset = vendor_details
        vendor_branch_map = {}
        vendor_branch_map[0] = branchObj
        for vendor in vendor_details:
            branch_details = branchObj.filter(vendor = vendor)
            vendor_branch_map[vendor.id] = branch_details
        if administratorObj.access_customers.all():
            context['form'].fields['customer_admin'].initial = True
        customer_list = Customer.objects.filter(branch__tenant = administratorObj.tenant)
        customer_choices = []
        for customer in customer_list:
            if customer.is_customer_complete_one():
                customer_choices.append([customer.id, customer.get_customer_branch_value()])
        if administratorObj.access_customer_groups.all():
            context['form'].fields['customer_admin'].initial = True
        customer_group_list = CustomerGroup.objects.filter(tenant = administratorObj.tenant)
        customer_group_choices = []
        for customer_group in customer_group_list:
            customer_group_choices.append([customer_group.id, customer_group.name])
        status_choices = []
        status_choices.append([-1, '--------------'])
        for status in status_list:
            status_choices.append([status.id, status.name])
        designation_choices = []
        designation_choices.append([-1, '--------------'])
        for designation in designation_list:
            designation_choices.append([designation.id, designation.name])
        roles_choices = []
        for roles in roles_list:
            roles_choices.append([roles.id, roles.name])
        context['form'].fields['access_customers'].choices =  customer_choices
        context['form'].fields['access_customer_groups'].choices =  customer_group_choices
        context['vendor_branch_map'] = vendor_branch_map
        context['form'].fields['access_branches'].initial = administratorObj.access_branches
        context['form'].fields['roles'].choices =  roles_choices
        context['form'].fields['status'].choices =  status_choices
        context['form'].fields['designation'].choices =  designation_choices
        return context

    def form_valid(self, form):
        adminObj = Administrator.objects.get(pk=self.request.user.id)
        form.instance.mobile_number = validate_mobile_countryCode(self.request.POST.get('mobile_number'))
        return super(UpdateAdministratorDetails,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(UpdateAdministratorDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateAdministratorDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        administrator_details = Administrator.objects.get(pk = self.kwargs['pk'])
        kw['administrator_details'] = administrator_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Administrator details sucessfully!'
        return super(UpdateAdministratorDetails, self).post(request, args, kwargs)
    
    def get_success_url(self):
        return reverse('administrations:list_administrators')

    
@class_view_decorator(login_required)
class DataUpload(AdminFormView):
    form_class = DataUploadForm
    template_name = 'data_upload.html'

    def get_context_data(self, **kwargs):
        context = super(DataUpload, self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        item_choices = []
        item_choices.append([0, '-----------'])
        item_choices.append([2, 'Asset'])
        item_choices.append([4, 'Asset Make'])
        item_choices.append([5, 'Asset Model'])
        item_choices.append([3, 'Asset Type'])
        item_choices.append([1, 'Customer'])
        context['form'].fields['item'].choices = item_choices
        return context

    def get(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        return super(DataUpload, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        config_map = None
        #config_map = request.config_map
        success = False
        process_time = get_datetime_disp_value(timezone.now(), request.session['SHORT_DATE_TIME_FORMAT'], request.session['DEFAULT_TIME_ZONE'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        request.session['uploaded_list'] = None
        request.session['error_list'] = None
        form = self.form_class(data=request.POST)
        update_existing_records = False
        if not form.is_valid():
            logger.debug('Form is invalid')
        else:
            customer = None
            upload_customer = False
            upload_machine = False
            upload_machine_type = False
            upload_machine_make = False
            upload_machine_model = False
            item_id = request.POST['item']
            if int(item_id) == 1:
                upload_customer = True
            elif int(item_id) == 2:    
                upload_machine = True
            elif int(item_id) == 3:    
                upload_machine_type = True
            elif int(item_id) == 4:    
                upload_machine_make = True
            elif int(item_id) == 5:    
                upload_machine_model = True
            datafile = self.request.FILES.get('file', None)
            if not datafile:
                messages.error(request, 'Please upload a file and submit')
            else:
                extension = find_file_extension(datafile.name)
                if extension != 'xls' and extension != 'xlsx' and extension != 'ods':
                    messages.error(request, 'Invalid file, please upload xls / xlsx / ods format files')
                else:
                    excel_data_map = {}
                    to_continue = True
                    try:
                        # print('dataFile: ', datafile)
                        book_items = datafile.get_book_dict().items()
                    except Exception as e:
                        # print ('Error: ', e)
                        messages.error(request, 'The uploaded excel file has some errors. Please check if invalid values are entered for any date field.')
                        to_continue = False
                    if to_continue:
                        for sheet_data in book_items:
                            sheet_name = sheet_data[0]
                            excel_data_map[sheet_name] = []
                            first_row = True
                            column_names = []
                            for row_data in sheet_data[1]:
                                if first_row:
                                    column_names = row_data
                                    first_row = False
                                else:
                                    row_data_map = {}
                                    col_num = 0
                                    for cell in row_data:
                                        col_name = column_names[col_num]
                                        row_data_map[col_name] = cell
                                        col_num += 1
                                    excel_data_map[sheet_name].append(row_data_map)
                        try:
                            ProcessBulkUploadThread(admin_user, process_time, excel_data_map, upload_customer, upload_machine, upload_machine_type, upload_machine_make, upload_machine_model).start()
                            messages.success(request, 'Upload request has been received successfully. You will be intimated via email once the request is processed.')
                            success = True
                        except Exception as e:
                            logger.error('Error while uploading bulkupload sheet')
                            logger.error(e)
                            messages.error(request, 'We are unable to process your bulk upload request. Please try after sometime and if problem persists, contact customer support.')
        item_choices = []
        item_choices.append([0, '-----------'])
        item_choices.append([2, 'Asset'])
        item_choices.append([4, 'Asset Make'])
        item_choices.append([5, 'Asset Model'])
        item_choices.append([3, 'Asset Type'])
        item_choices.append([1, 'Customer'])
        form.fields['item'].choices = item_choices
        return render(request, 'data_upload.html', {'form':form, 'success':success})
    
class ProcessBulkUploadThread(threading.Thread):

    def __init__(self, admin_user, process_time, excel_data_map, upload_customer, upload_machine, upload_machine_type, upload_machine_make, upload_machine_model, **kwargs):
        self.admin_user = admin_user
        self.process_time = process_time
        self.excel_data_map = excel_data_map
        self.upload_customer = upload_customer
        self.upload_machine = upload_machine
        self.upload_machine_type = upload_machine_type
        self.upload_machine_make = upload_machine_make
        self.upload_machine_model = upload_machine_model
        super(ProcessBulkUploadThread, self).__init__(**kwargs)

    def run(self):
        logger.info('Started running bulk data process thread')
        is_bug = False
        bug_list = []
        upload_done = False
        error_list = []
        customers_list = []
        machines_list = []
        customers_map = {}
        machines_map = {}
        machine_type_list = []
        machine_type_map = {}
        machine_make_list = []
        machine_make_map = {}
        machine_model_list = []
        machine_model_map = {}
        vehicles_list = []
        uploaded_list = []
        row_num = 0
        is_error = False
        is_warn = False
        #config_map = self.config_map
        process_time = self.process_time
        excel_data_map = self.excel_data_map
        admin_user = self.admin_user
        upload_customer = self.upload_customer
        upload_machine = self.upload_machine
        upload_machine_type = self.upload_machine_type
        upload_machine_make = self.upload_machine_make
        upload_machine_model = self.upload_machine_model
        #customer = self.customer
        CUSTOMER_NAME = 'Customer Name *'
        PHONE_NUMBER = 'Contact Number *'
        BRANCH = 'Branch *'
        EMAIL = 'Email *'
        ADDRESS = 'Address *'
        PINCODE = 'Pincode *'
        CUSTOMER_STATUS = 'Status *'
        SPOC_NAME = 'Spoc Name *'
        ALTERNATE_PHONE = 'Alternate Contact No'
        IS_PREMIUM = 'Is Premium?'
        CUSTOMER_COMMENTS = 'Comments'
        CUSTOMER_VENDOR = 'Client *'
        MACHINE_CUSTOMER_NAME = 'Customer Name *'
        MACHINE_CUSTOMER_ADDRESS = 'Address *'
        MACHINE_SERIAL_NUMBER = 'Serial Number *'
        MACHINE_MTM_NUMBER = 'Mtm Number'
        MACHINE_STATUS = 'Status *'
        MACHINE_MODEL = 'Model *'
        MACHINE_WARRANTY_TYPE = 'Support Type'
        MACHINE_WARRANTY_DETAILS = 'Warranty Details'
        MACHINE_AMC_START_DATE = 'Start Date'
        MACHINE_AMC_END_DATE = 'End Date'
        MACHINE_HDD_RETENTION = 'Hard Disk Retention'
        MACHINE_ACCIDENT_DAMAGE_COVER = 'Accident Damage Cover'
        MACHINE_CUSTOMER_INDUCED_DAMAGE = 'Customer Induced Damage'
        MACHINE_CRU = 'CRU Machine'
        MACHINE_COMMENTS = 'Comments'
        MACHINE_VENDOR = 'Client *'
        MACHINE_TYPE_NAME = 'Type Name *'
        MACHINE_MAKE_NAME = 'Make Name *'
        MACHINE_MODEL_NAME = 'Model Name *'
        MACHINE_MODEL_TYPE = 'Asset Type *'
        MACHINE_MODEL_MAKE = 'Asset Make *'
        ASSEST_ID = 'Assest ID'
        USER_NAME = 'User Name'
        USER_EMPLOYEE_ID = 'User Employee ID'
        USER_DESIGNATION = 'User Designation'
        LOCATION = 'Location'
        REPORTING_MANAGER_EMAIL = 'Reporting Manager Email'
        FLOOR = 'Floor'
        BUILDING_NAME = 'Building Name'
        PROCESSOR_SPEED = 'Processor Speed'
        MONITOR_MAKE = 'Monitor Make'
        MONITOR_SIZE = 'Monitor Size'
        HOST_NAME = 'Host Name'
        MAC_ADDRESS = 'MAC Address'
        IP_ADDRESS = 'IP Address'
        ANTI_VIRUS_NAME = 'Anti Virus Name'
        ANTI_VIRUS_SERIAL_NUMBER = 'Anti Virus Serial Number'
        ANTI_VIRUS_KEY = 'Anti Virus Key'
        ANTI_VIRUS_EXPIRY_DATE = 'Anti Virus Exipry Date'
        SOFTWARES = 'Softwares'
        OPERATING_SYSTEM = 'Operating System'
        RAM = 'RAM'
        HARD_DISK_TYPE = 'Hard Disk Type'
        CAPACITY_IN_RAM = 'Capacity in RAM'
        CAPACITY_IN_HDD = 'Capacity in HDD'
        try:
            if upload_customer:
                try:
                    customer_records = excel_data_map['Customer']
                    first_unit_record = customer_records[0]
                    try:
                        first_unit_record[CUSTOMER_NAME]
                        first_unit_record[PHONE_NUMBER]
                        first_unit_record[BRANCH]
                        first_unit_record[CUSTOMER_VENDOR]
                        first_unit_record[EMAIL]
                        first_unit_record[ADDRESS]
                        first_unit_record[PINCODE]
                        #first_unit_record[CUSTOMER_STATUS]
                        first_unit_record[SPOC_NAME]
                        first_unit_record[ALTERNATE_PHONE]
                        #first_unit_record[IS_PREMIUM]
                        first_unit_record[CUSTOMER_COMMENTS]
                    except:
                        logger.info('Invalid Unit template used')
                        customer_records = []
                        customers_map = {}
                        error_list.append(BulkUploadErrorData('Customer', '-NA-', 2, "Invalid template used, please use the updated template from link provided at the top right corner"))
                        is_error = True
                        send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                        return
                except:
                    customer_records = []


                for i, record in enumerate(customer_records):
                    row_num = i + 2
                    customer_name_str = record[CUSTOMER_NAME].strip()
                    formatted_phone_number = transform_phone(str(record[PHONE_NUMBER]))
                    formatted_alt_phone_number = transform_phone(str(record[ALTERNATE_PHONE]))
                    default_branch_str = record[BRANCH].strip()
                    default_vendor_str = record[CUSTOMER_VENDOR].strip()
                    default_email_str = record[EMAIL].strip()
                    default_address_str = record[ADDRESS].strip()
                    default_spoc_str = record[SPOC_NAME].strip()
                    default_pincode_str = str(record[PINCODE]).strip()
                    #default_customer_status_str = record[CUSTOMER_STATUS].strip()
                    default_customer_status_str = 'Approved'
                    default_customer_comments_str = record[CUSTOMER_COMMENTS].strip()
                    
                    is_premium = False
                    #is_premium_str = record[IS_PREMIUM].strip()
                    #if is_premium_str:
                    #    try:
                    #        premium = int(is_premium_str)
                    #        if premium > 0:
                    #            is_premium = True
                    #    except:
                    #        pass
                    #customer = Customer(name = customer_name_str, phone = formatted_phone_number, alt_phone = formatted_alt_phone_number, email = default_email_str, address = default_address_str, pin_code = default_pincode_str, is_premium = is_premium, comments = default_customer_comments_str, spoc_name = default_spoc_str)
                    customer = Customer(name = customer_name_str, phone = formatted_phone_number, alt_phone = formatted_alt_phone_number, email = default_email_str, address = default_address_str, pin_code = default_pincode_str, is_premium = is_premium, comments = default_customer_comments_str, spoc_name = default_spoc_str)
                    validated_data = validate_customer(customer, admin_user, customers_map, default_branch_str, default_customer_status_str, default_vendor_str)
                    customers_list.append(customer)
                    name_pincode = str(customer_name_str) + str(default_address_str) 
                    customers_map[name_pincode] = customer
                    if validated_data[0] != 0:
                        error_list.append(BulkUploadErrorData('Customer', row_num, validated_data[0], validated_data[1]))
                        if validated_data[0] == 2:
                            is_error = True
                        elif validated_data[0] == 1:
                            is_warn = True
                if is_error:
                    logger.info('No data processed due to error(s) in Customer sheet')
                    send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                    return


                num_insert = 0
                num_update = 0
                num_delete = 0
                for customer in customers_list:
                    if customer.is_update:
                        custobj = Customer.objects.get(name = customer.name, pin_code = customer.pin_code)
                        custobj.phone = customer.phone
                        custobj.alt_phone = customer.alt_phone
                        custobj.email = customer.email
                        custobj.address = customer.address
                        custobj.is_premium = customer.is_premium
                        custobj.comments = customer.comments
                        custobj.save()
                        num_update += 1
                    else:
                        customer.save()
                        num_insert += 1
                if num_insert > 0 or num_update > 0:
                    uploaded_list.append(BulkUploadCount('Customer', num_insert, num_update, num_delete))
                    upload_done = True

            if upload_machine:
                try:
                    machine_records = excel_data_map['Asset']
                    first_unit_record = machine_records[0]
                    try:
                        first_unit_record[MACHINE_CUSTOMER_NAME]
                        first_unit_record[MACHINE_CUSTOMER_ADDRESS]
                        first_unit_record[MACHINE_VENDOR]
                        first_unit_record[MACHINE_SERIAL_NUMBER]
                        #first_unit_record[MACHINE_MTM_NUMBER]
                        first_unit_record[MACHINE_STATUS]
                        first_unit_record[MACHINE_MODEL]
                        first_unit_record[MACHINE_WARRANTY_TYPE]
                        first_unit_record[MACHINE_WARRANTY_DETAILS]
                        first_unit_record[MACHINE_AMC_START_DATE]
                        first_unit_record[MACHINE_AMC_END_DATE]
                        #first_unit_record[MACHINE_HDD_RETENTION]
                        #first_unit_record[MACHINE_ACCIDENT_DAMAGE_COVER]
                        #first_unit_record[MACHINE_CUSTOMER_INDUCED_DAMAGE]
                        #first_unit_record[MACHINE_CRU]
                        first_unit_record[MACHINE_COMMENTS]
                        first_unit_record[ASSEST_ID]
                        first_unit_record[USER_NAME]
                        first_unit_record[USER_EMPLOYEE_ID]
                        first_unit_record[USER_DESIGNATION]
                        first_unit_record[LOCATION]
                        first_unit_record[REPORTING_MANAGER_EMAIL]
                        first_unit_record[FLOOR]
                        first_unit_record[BUILDING_NAME]
                        first_unit_record[PROCESSOR_SPEED]
                        first_unit_record[MONITOR_MAKE]
                        first_unit_record[MONITOR_SIZE]
                        first_unit_record[HOST_NAME]
                        first_unit_record[MAC_ADDRESS]
                        first_unit_record[IP_ADDRESS]
                        first_unit_record[ANTI_VIRUS_NAME]
                        first_unit_record[ANTI_VIRUS_SERIAL_NUMBER]
                        first_unit_record[ANTI_VIRUS_KEY]
                        first_unit_record[ANTI_VIRUS_EXPIRY_DATE]
                        first_unit_record[SOFTWARES]
                        first_unit_record[OPERATING_SYSTEM]
                        first_unit_record[RAM]
                        first_unit_record[HARD_DISK_TYPE]
                        first_unit_record[CAPACITY_IN_RAM]
                        first_unit_record[CAPACITY_IN_HDD]

                    except:
                        logger.info('Invalid Asset template used')
                        machine_records = []
                        machines_map = {}
                        error_list.append(BulkUploadErrorData('Asset', '-NA-', 2, "Invalid template used, please use the updated template from link provided at the top right corner"))
                        is_error = True
                        send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                        return
                except:
                    machine_records = []


                for i, record in enumerate(machine_records):
                    row_num = i + 2
                    default_machine_customer_name_str = record[MACHINE_CUSTOMER_NAME].strip()
                    default_machine_address_str = str(record[MACHINE_CUSTOMER_ADDRESS]).strip()
                    default_serial_number_str = str(record[MACHINE_SERIAL_NUMBER]).strip()
                    #default_mtm_number_str = str(record[MACHINE_MTM_NUMBER]).strip()
                    default_mtm_number_str = ''
                    default_model_str = record[MACHINE_MODEL].strip()
                    default_vendor_str = record[MACHINE_VENDOR].strip()
                    default_warranty_type_str = record[MACHINE_WARRANTY_TYPE].strip()
                    default_warranty_details_str = record[MACHINE_WARRANTY_DETAILS].strip()
                    default_amc_start_date_str = record[MACHINE_AMC_START_DATE]
                    default_amc_end_date_str = record[MACHINE_AMC_END_DATE]
                    default_machine_status_str = record[MACHINE_STATUS].strip()
                    default_comments_str = record[MACHINE_COMMENTS].strip()
                    default_assest_id_str = str(record[ASSEST_ID]).strip()
                    default_user_name_str = str(record[USER_NAME]).strip()
                    default_user_employee_id_str = str(record[USER_EMPLOYEE_ID]).strip()
                    default_user_designation_str = str(record[USER_DESIGNATION]).strip()
                    default_location_str = str(record[LOCATION]).strip()
                    default_reporting_manager_email_str = str(record[REPORTING_MANAGER_EMAIL]).strip()
                    default_floor_str = str(record[FLOOR]).strip()
                    default_building_name_str = str(record[BUILDING_NAME]).strip()
                    default_processor_speed_str = str(record[PROCESSOR_SPEED]).strip()
                    default_monitor_make_str = str(record[MONITOR_MAKE]).strip()
                    default_monitor_size_str = str(record[MONITOR_SIZE]).strip()
                    default_host_name_str = str(record[HOST_NAME]).strip()
                    default_MAC_address_str = str(record[MAC_ADDRESS]).strip()
                    default_IP_address_str = str(record[IP_ADDRESS]).strip()
                    default_anti_virus_name_str = str(record[ANTI_VIRUS_NAME]).strip()
                    default_anti_virus_serial_number_str = str(record[ANTI_VIRUS_SERIAL_NUMBER]).strip()
                    default_anti_virus_key_str = str(record[ANTI_VIRUS_KEY]).strip()
                    default_anti_virus_expiry_date_str = str(record[ANTI_VIRUS_EXPIRY_DATE]).strip()
                    default_softwares_str = str(record[SOFTWARES]).strip()
                    default_operating_system_str = str(record[OPERATING_SYSTEM]).strip()
                    default_ram_type_str = str(record[RAM]).strip()
                    default_hard_disk_type_str = str(record[HARD_DISK_TYPE]).strip()
                    default_ram_capacity_value_str = str(record[CAPACITY_IN_RAM]).strip()
                    default_hardisktype_capacity_value_str = str(record[CAPACITY_IN_HDD]).strip()
                    #default_cru_machine_str = record[MACHINE_CRU].strip()
                    default_cru_machine_str = ''
                    hard_disk_retention = False
                    #hard_disk_retention_str = str(record[MACHINE_HDD_RETENTION]).strip()
                    #if hard_disk_retention_str:
                    #    try:
                    #        hard_disk_retention_int = int(hard_disk_retention_str)
                    #        if hard_disk_retention_int > 0:
                    #            hard_disk_retention = True
                    #    except:
                    #        pass
                    accident_damage_cover = False
                    #accident_damage_cover_str = str(record[MACHINE_ACCIDENT_DAMAGE_COVER]).strip()
                    #if accident_damage_cover_str:
                    #    try:
                    #        accident_damage_cover_int = int(accident_damage_cover_str)
                    #        if accident_damage_cover_int > 0:
                    #            accident_damage_cover = True
                    #    except:
                    #        pass
                    customer_induced_damage = False
                    #customer_induced_damage_str = str(record[MACHINE_CUSTOMER_INDUCED_DAMAGE]).strip()
                    #if customer_induced_damage_str:
                    #    try:
                    #        customer_induced_damage_int = int(customer_induced_damage_str)
                    #        if customer_induced_damage_int > 0:
                    #            customer_induced_damage = True
                    #    except:
                    #        pass
                    machine = Machine(serial_number = default_serial_number_str, mtm_number = default_mtm_number_str, warranty_details = default_warranty_details_str, hard_disk_retention = hard_disk_retention, accident_damage_cover = accident_damage_cover, customer_induced_damage = customer_induced_damage, cru_machine = default_cru_machine_str, comments = default_comments_str, assest_id = default_assest_id_str, user_name = default_user_name_str, user_employee_id  = default_user_employee_id_str, user_designation = default_user_designation_str, location = default_location_str, reporting_manager_email = default_reporting_manager_email_str, floor = default_floor_str, building_name = default_building_name_str, processor_speed = default_processor_speed_str, monitor_make = default_monitor_make_str, monitor_size = default_monitor_size_str, host_name = default_host_name_str, mac_address = default_MAC_address_str, ip_address = default_IP_address_str, anti_virus_name = default_anti_virus_name_str, anti_virus_serial_number = default_anti_virus_serial_number_str, anti_virus_key = default_anti_virus_key_str, anti_virus_expiry_date = default_anti_virus_expiry_date_str, softwares = default_softwares_str)
                    validated_data = validate_machine(machine, admin_user, machines_map, default_machine_customer_name_str, default_machine_address_str, default_model_str, default_warranty_type_str, default_machine_status_str, default_amc_start_date_str, default_amc_end_date_str, default_vendor_str, default_operating_system_str, default_ram_type_str, default_hard_disk_type_str, default_ram_capacity_value_str, default_hardisktype_capacity_value_str)
                    machines_list.append(machine)
                    machines_map[default_serial_number_str] = machine
                    if validated_data[0] != 0:
                        error_list.append(BulkUploadErrorData('Asset', row_num, validated_data[0], validated_data[1]))
                        if validated_data[0] == 2:
                            is_error = True
                        elif validated_data[0] == 1:
                            is_warn = True
                if is_error:
                    logger.info('No data processed due to error(s) in Asset sheet')
                    send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                    return


                num_insert = 0
                num_update = 0
                num_delete = 0
                for machine in machines_list:
                    if machine.is_update:
                        num_update += 1
                    else:
                        machine.save()
                        num_insert += 1
                if num_insert > 0 or num_update > 0:
                    uploaded_list.append(BulkUploadCount('Asset', num_insert, num_update, num_delete))
                    upload_done = True

            if upload_machine_type:
                try:
                    machine_type_records = excel_data_map['AssetType']
                    first_unit_record = machine_type_records[0]
                    try:
                        first_unit_record[MACHINE_TYPE_NAME]
                    except:
                        logger.info('Invalid Asset Type template used')
                        machine_type_records = []
                        machine_type_map = {}
                        error_list.append(BulkUploadErrorData('AssetType', '-NA-', 2, "Invalid template used, please use the updated template from link provided at the top right corner"))
                        is_error = True
                        send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                        return
                except:
                    machine_type_records = []


                for i, record in enumerate(machine_type_records):
                    row_num = i + 2
                    default_machine_type_name_str = record[MACHINE_TYPE_NAME].strip()
                    default_rank = 0
                    machinetype = MachineType(name = default_machine_type_name_str, rank = default_rank, tenant = admin_user.tenant)
                    validated_data = validate_machine_type(machinetype, admin_user, machine_type_map)
                    machine_type_list.append(machinetype)
                    machine_type_map[default_machine_type_name_str] = machinetype
                    if validated_data[0] != 0:
                        error_list.append(BulkUploadErrorData('AssetType', row_num, validated_data[0], validated_data[1]))
                        if validated_data[0] == 2:
                            is_error = True
                        elif validated_data[0] == 1:
                            is_warn = True
                if is_error:
                    logger.info('No data processed due to error(s) in AssetType sheet')
                    send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                    return


                num_insert = 0
                num_update = 0
                num_delete = 0
                for machinetype in machine_type_list:
                    if machinetype.is_update:
                        num_update += 1
                    else:
                        machinetype.save()
                        num_insert += 1
                if num_insert > 0 or num_update > 0:
                    uploaded_list.append(BulkUploadCount('AssetType', num_insert, num_update, num_delete))
                    upload_done = True

            if upload_machine_make:
                try:
                    machine_make_records = excel_data_map['AssetMake']
                    first_unit_record = machine_make_records[0]
                    try:
                        first_unit_record[MACHINE_MAKE_NAME]
                    except:
                        logger.info('Invalid Asset Make template used')
                        machine_make_records = []
                        machine_make_map = {}
                        error_list.append(BulkUploadErrorData('AssetMake', '-NA-', 2, "Invalid template used, please use the updated template from link provided at the top right corner"))
                        is_error = True
                        send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                        return
                except:
                    machine_make_records = []


                for i, record in enumerate(machine_make_records):
                    row_num = i + 2
                    default_machine_make_name_str = record[MACHINE_MAKE_NAME].strip()
                    default_rank = 0
                    machinemake = MachineMake(name = default_machine_make_name_str, rank = default_rank, tenant = admin_user.tenant)
                    validated_data = validate_machine_make(machinemake, admin_user, machine_make_map)
                    machine_make_list.append(machinemake)
                    machine_make_map[default_machine_make_name_str] = machinemake
                    if validated_data[0] != 0:
                        error_list.append(BulkUploadErrorData('AssetMake', row_num, validated_data[0], validated_data[1]))
                        if validated_data[0] == 2:
                            is_error = True
                        elif validated_data[0] == 1:
                            is_warn = True
                if is_error:
                    logger.info('No data processed due to error(s) in AssetMake sheet')
                    send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                    return


                num_insert = 0
                num_update = 0
                num_delete = 0
                for machinemake in machine_make_list:
                    if machinemake.is_update:
                        num_update += 1
                    else:
                        machinemake.save()
                        num_insert += 1
                if num_insert > 0 or num_update > 0:
                    uploaded_list.append(BulkUploadCount('AssetMake', num_insert, num_update, num_delete))
                    upload_done = True

            if upload_machine_model:
                try:
                    machine_model_records = excel_data_map['AssetModel']
                    first_unit_record = machine_model_records[0]
                    try:
                        first_unit_record[MACHINE_MODEL_NAME]
                        first_unit_record[MACHINE_MODEL_TYPE]
                        first_unit_record[MACHINE_MODEL_MAKE]
                    except:
                        logger.info('Invalid Asset Model template used')
                        machine_model_records = []
                        machine_model_map = {}
                        error_list.append(BulkUploadErrorData('AssetModel', '-NA-', 2, "Invalid template used, please use the updated template from link provided at the top right corner"))
                        is_error = True
                        send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                        return
                except:
                    machine_model_records = []


                for i, record in enumerate(machine_model_records):
                    row_num = i + 2
                    default_machine_model_name_str = record[MACHINE_MODEL_NAME].strip()
                    default_machine_model_type_str = record[MACHINE_MODEL_TYPE].strip()
                    default_machine_model_make_str = record[MACHINE_MODEL_MAKE].strip()
                    default_rank = 0
                    machinemodel = MachineModel(name = default_machine_model_name_str, rank = default_rank)
                    validated_data = validate_machine_model(machinemodel, admin_user, machine_model_map, default_machine_model_type_str, default_machine_model_make_str)
                    machine_model_list.append(machinemodel)
                    machine_model_map[default_machine_model_name_str] = machinemodel
                    if validated_data[0] != 0:
                        error_list.append(BulkUploadErrorData('AssetModel', row_num, validated_data[0], validated_data[1]))
                        if validated_data[0] == 2:
                            is_error = True
                        elif validated_data[0] == 1:
                            is_warn = True
                if is_error:
                    logger.info('No data processed due to error(s) in AssetModel sheet')
                    send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list)
                    return


                num_insert = 0
                num_update = 0
                num_delete = 0
                for machinemodel in machine_model_list:
                    if machinemodel.is_update:
                        num_update += 1
                    else:
                        machinemodel.save()
                        num_insert += 1
                if num_insert > 0 or num_update > 0:
                    uploaded_list.append(BulkUploadCount('AssetModel', num_insert, num_update, num_delete))
                    upload_done = True
            if not is_warn and not is_error and not upload_done:
                if upload_customer:
                    error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Empty File Uploaded or Invalid template used for Customer Upload.</font>"))
                elif upload_machine:
                    error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Empty File Uploaded or Invalid template used for Asset Upload.</font>"))
                elif upload_machine_type:
                    error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Empty File Uploaded or Invalid template used for Asset Type Upload.</font>"))
                elif upload_machine_make:
                    error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Empty File Uploaded or Invalid template used for Asset Make Upload.</font>"))
                elif upload_machine_model:
                    error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Empty File Uploaded or Invalid template used for Asset Model Upload.</font>"))
                else:
                    error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Empty File Uploaded or Invalid template used.</font>"))
                is_error = True
            send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list, uploaded_list)
            logger.info('Bulk data process thread ended')
        except Exception as e:
            logger.error('Error during bulk upload')
            logger.error(e)
            body = traceback.format_exc()
            logger.error(body)
            error_list.append(BulkUploadErrorData('-NA-', '-NA-', 2, "<font style='color:red'>Something went wrong, please check with customer support.</font>"))
            is_error = True
            send_bulk_upload_status_email(admin_user, process_time, is_warn, False, is_error, error_list)
            subject = 'Bulk Upload Issue - ' + str(process_time)
            try:
                send_email_message([admin_user.email], subject, body)
            except Exception:
                logger.warn("Unable to send bulk upload bug email")

def validate_customer(customer, admin_user, customers_map, default_branch_str, default_customer_status_str, default_vendor_str):
    process_code = 0
    process_status = ''
    is_error = False
    is_warn = False
    is_update = False
    vendor = None
    if customer.name:
        if len(smart_str(customer.name)) > 75:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Customer Name should not be greater than 75 characters</font>'
    else:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Customer Name field is Empty</font>'
    if default_vendor_str:
        vendor = Vendor.objects.filter(name__iexact = default_vendor_str, is_active = True).first()
        if vendor:
            allow_customer_creation = TenantVendorMapping.objects.filter(tenant = admin_user.tenant, vendor = vendor, allow_customer_creation = True).first()
            if not allow_customer_creation:
                vendor = None
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Customer Creation is not valid for this Client</font>'
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Client value is Invalid</font>'    
    else:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Client field is Empty</font>'
    if not customer.phone:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Contact Number field is Empty</font>'
    else:
        validPhoneVal = validate_mobile_countryCode(customer.phone)
        if not validPhoneVal:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Contact Number field is Invalid</font>'
        else:
            customer.phone = validPhoneVal
            if Customer.objects.filter(branch__tenant = admin_user.tenant, phone = validPhoneVal).exists():
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Contact Number already exists in Application</font>'
    if not customer.email:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Email field is Empty</font>'
    if not customer.address:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Address field is Empty</font>'
    if not customer.pin_code:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Pin Code field is Empty</font>'
    else:
        if not customer.pin_code.isdigit():
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Pincode Value is Invalid!</font>'
    if not customer.spoc_name:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Spoc Name field is Empty</font>'
    if not default_branch_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Branch is Empty</font>'
    else:
        if vendor:
            branch = Branch.objects.filter(name__iexact = default_branch_str, tenant = admin_user.tenant, is_active = True, vendor = vendor).first()
            if branch:
                customer.branch = branch
            else:
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Branch is invalid</font>'
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Branch cannot be validated due to Invalid Client</font>'            
    if not default_customer_status_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Customer Status field is Empty</font>'
    else:
        status = CustomerStatus.objects.filter(name__iexact = default_customer_status_str, tenant = admin_user.tenant, is_active = True).first()
        if status:
            customer.status = status
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Customer Status is invalid</font>'
    if customer.name and customer.address:
        name_pincode = str(customer.name) + str(customer.address) 
        if customers_map.get(name_pincode):
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Duplicate Customer in the uploaded file</font>'
        if Customer.objects.filter(name__iexact = customer.name, address__iexact = customer.address).exists():
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Customer with name and pincode already exists in Application</font>'
    if is_error:
        process_code = 2
    elif is_warn:
        process_code = 1
    customer.is_update = is_update
    return [process_code, process_status]

def validate_machine(machine, admin_user, machines_map, default_machine_customer_name_str, default_machine_address_str, default_model_str, default_warranty_type_str, default_machine_status_str, default_amc_start_date_str, default_amc_end_date_str, default_vendor_str, default_operating_system_str, default_ram_type_str, default_hard_disk_type_str, default_ram_capacity_value_str, default_hardisktype_capacity_value_str):
    process_code = 0
    process_status = ''
    is_error = False
    is_warn = False
    is_update = False
    vendor = None
    if default_vendor_str:
        vendor = Vendor.objects.filter(name__iexact = default_vendor_str, is_active = True).first()
        if vendor:
            allow_customer_creation = TenantVendorMapping.objects.filter(tenant = admin_user.tenant, vendor = vendor, allow_customer_creation = True).first()
            if not allow_customer_creation:
                vendor = None
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Asset Creation is not valid for this Client</font>'
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Client value is Invalid</font>'    
    else:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Client field is Empty</font>'
    if not default_machine_customer_name_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Customer Name field is Empty</font>'
    if not default_machine_address_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Address field is Empty</font>'
    customer = None    
    if default_machine_customer_name_str and default_machine_address_str:
        if vendor:
            customer = Customer.objects.filter(name__iexact = default_machine_customer_name_str, address__iexact = default_machine_address_str, branch__vendor = vendor).first()
            if customer:
                machine.customer = customer
            else:
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">There is no customer found in application matching provided Customer Name and Address</font>'
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Customer cannot be validated due to Invalid Client</font>'            
    if not machine.serial_number:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Serial Number field is Empty</font>'
    else:
        if machines_map.get(machine.serial_number):
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Duplicate Serial Number in the uploaded file</font>'        
        if Machine.objects.filter(serial_number__iexact = machine.serial_number, customer__branch__tenant = admin_user.tenant).exists():
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Serial Number field Already exists in Application!</font>'                
    #if not machine.mtm_number:
    #    process_code = 2
    #    is_error = True
    #    if process_status:
    #        process_status += "  |  "
    #    process_status += '<font style="color:red">MTM Number field is Empty</font>'
    if not default_model_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Model field is Empty</font>'
    else:
        model = MachineModel.objects.filter(name__iexact = default_model_str, machine_type__tenant = admin_user.tenant, is_active = True).first()
        if model:
            machine.model = model
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Model is invalid</font>'
    if default_warranty_type_str:
        warranty_type = WarrantyType.objects.filter(name__iexact = default_warranty_type_str, tenant = admin_user.tenant, is_active = True).first()
        if warranty_type:
            machine.warranty_type = warranty_type
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Support Type is invalid</font>'
    if not default_machine_status_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Asset Status field is Empty</font>'
    else:
        status = AssetStatus.objects.filter(name__iexact = default_machine_status_str, tenant = admin_user.tenant, is_active = True).first()
        if status:
            machine.status = status
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Asset Status is invalid</font>'
    if default_operating_system_str:
        operating_system = OperatingSystem.objects.filter(name__iexact = default_operating_system_str, tenant = admin_user.tenant, is_active = True).first()
        if operating_system:
            machine.operating_system = operating_system
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Operating System is invalid</font>'
    if default_ram_type_str and default_ram_capacity_value_str:
        ram_capacity_obj = MemoryCapacity.objects.filter(name__iexact = default_ram_capacity_value_str, tenant = admin_user.tenant, is_active = True).first()
        if ram_capacity_obj:
            ram_type = RAM.objects.filter(name__iexact = default_ram_type_str, capacity = ram_capacity_obj, tenant = admin_user.tenant, is_active = True).first()
            if ram_type:
                machine.ram_type = ram_type
            else:
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">RAM is invalid</font>'
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Capacity in RAM is invalid</font>'
    if default_hard_disk_type_str and default_hardisktype_capacity_value_str:
        hard_disk_capacity_obj = MemoryCapacity.objects.filter(name__iexact = default_hardisktype_capacity_value_str, tenant = admin_user.tenant, is_active = True).first()
        if hard_disk_capacity_obj:
            hard_disk_type = HardiskType.objects.filter(name__iexact = default_hard_disk_type_str, capacity = hard_disk_capacity_obj, tenant = admin_user.tenant, is_active = True).first()
            if hard_disk_type:
                machine.hard_disk_type = hard_disk_type
            else:
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">HardiskType is invalid</font>'
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Capacity in HardiskType is invalid</font>'
    if  default_amc_start_date_str:
        machine.amc_start_date = default_amc_start_date_str
    if default_amc_end_date_str:
        machine.amc_end_date = default_amc_end_date_str 
    if is_error:
        process_code = 2
    elif is_warn:
        process_code = 1
    machine.is_update = is_update
    return [process_code, process_status]
    
def validate_machine_type(machinetype, admin_user, machine_type_map):
    process_code = 0
    process_status = ''
    is_error = False
    is_warn = False
    is_update = False
    if not machinetype.name:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Name field is Empty</font>'
    else:
        if machine_type_map.get(machinetype.name):
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Duplicate Name in the uploaded file</font>'        
        if MachineType.objects.filter(name__iexact = machinetype.name, tenant = admin_user.tenant).exists():
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Asset Type with this name already exists in Application!</font>'                
    if is_error:
        process_code = 2
    elif is_warn:
        process_code = 1
    machinetype.is_update = is_update
    return [process_code, process_status]

def validate_machine_make(machinemake, admin_user, machine_make_map):
    process_code = 0
    process_status = ''
    is_error = False
    is_warn = False
    is_update = False
    if not machinemake.name:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Name field is Empty</font>'
    else:
        if machine_make_map.get(machinemake.name):
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Duplicate Name in the uploaded file</font>'        
        if MachineMake.objects.filter(name__iexact = machinemake.name, tenant = admin_user.tenant).exists():
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Asset Make with this name already exists in Application!</font>'                
    if is_error:
        process_code = 2
    elif is_warn:
        process_code = 1
    machinemake.is_update = is_update
    return [process_code, process_status]

def validate_machine_model(machinemodel, admin_user, machine_model_map, default_machine_model_type_str, default_machine_model_make_str):
    process_code = 0
    process_status = ''
    is_error = False
    is_warn = False
    is_update = False
    if not machinemodel.name:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Name field is Empty</font>'
    else:
        if machine_model_map.get(machinemodel.name):
                process_code = 2
                is_error = True
                if process_status:
                    process_status += "  |  "
                process_status += '<font style="color:red">Duplicate Name in the uploaded file</font>'        
        if MachineModel.objects.filter(name__iexact = machinemodel.name, machine_type__tenant = admin_user.tenant).exists():
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Asset Model with this name already exists in Application!</font>'                
    if not default_machine_model_type_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Asset Type field is Empty</font>'
    else:
        machinetypeobj = MachineType.objects.filter(name__iexact = default_machine_model_type_str, tenant = admin_user.tenant, is_active = True).first()
        if machinetypeobj:
            machinemodel.machine_type = machinetypeobj
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Asset Type is invalid</font>'
    if not default_machine_model_make_str:
        process_code = 2
        is_error = True
        if process_status:
            process_status += "  |  "
        process_status += '<font style="color:red">Asset Make field is Empty</font>'
    else:
        machinemakeobj = MachineMake.objects.filter(name__iexact = default_machine_model_make_str, tenant = admin_user.tenant, is_active = True).first()
        if machinemakeobj:
            machinemodel.machine_make = machinemakeobj
        else:
            process_code = 2
            is_error = True
            if process_status:
                process_status += "  |  "
            process_status += '<font style="color:red">Asset Make is invalid</font>'
    if is_error:
        process_code = 2
    elif is_warn:
        process_code = 1
    machinemodel.is_update = is_update
    return [process_code, process_status]

def send_bulk_upload_status_email(admin_user, process_time, is_warn, upload_done, is_error, error_list, uploaded_list=None):
    message = 'No data processed due to error(s) in uploaded file'
    uploaded_list_value = ''
    error_list_value = ''
    body = ''
    subject = 'Bulk Upload Status : ' + str(process_time)
    name = admin_user.first_name + ' ' + admin_user.last_name
    sender_name = 'HCMS Team'
    from_email = settings.EMAIL_FROM
    if is_warn:
        logger.info('Data processed with some warnings')
        message = 'Data processed with some warnings. Uploaded count is as below:'
        if not upload_done:
            message = 'Data processed with some warnings'
    elif upload_done:
        logger.info('Data processed successfully')
        message = 'Data processed successfully. Uploaded count is as below:'
    elif not is_error:
        logger.info('No data processed due to empty file uploaded')
        message = 'No data processed due to empty file uploaded'
    if is_warn or is_error:
        for obj in error_list:
            error_list_value += '<tr><td style="text-align:center">' + obj.table + '</td><td style="text-align:center">' + str(obj.row_num) + '</td><td style="text-align:center">' + error_code_to_string(obj.error_type) + '</td><td style="text-align:center">' + str(obj.error_reason) + '</td></tr>'
    if upload_done:
        if uploaded_list:
            for obj in uploaded_list:
                uploaded_list_value += '<tr><td style="text-align:center">'+obj.table+'</td><td style="text-align:center">'+str(obj.no_of_inserted_rows)+'</td><td style="text-align:center">'+str(obj.no_of_updated_rows)+'</td><td style="text-align:center">'+str(obj.no_of_deleted_rows)+'</td></tr>'
    if is_warn and upload_done:
        body_html = '<div style="background-color: #ffffff; padding-left:10%;padding-top:30px;width:645px;"> <div style="border:1px solid #ebecf7; background-color: #f3f4f7;width:100%;"> <div style="padding-left: 40px;padding-top: 20px;padding-bottom: 10px;padding-right: 10px;color:#000080;"> <b style="font-size:20px;">Dear $1$,</b> <br/><br/> <span>Your request to the bulk upload has been completed with the status [<b>$2$</b>]</span> <br/><br/> <div class="row"><div class="col-xs-12" style="display: flex;justify-content: center;"><table border="2" bordercolor="blue"><thead><tr><th>Sheet Name</th><th>No of Inserted Rows</th><th>No of Updated Rows</th><th>No of Deleted Rows</th></tr></thead><tbody>$3$</table></div><br/><br/><div class="col-xs-12" style="display: flex;justify-content: center;"><table border="2" bordercolor="blue"><thead><tr><th>Sheet Name</th><th>Row Number</th><th>Error Type</th><th>Error Reason</th></tr></thead><tbody>$4$</table></div></div></div> <div style="padding-left: 40px;padding-top: 15px;padding-bottom: 10px; border-top:2px solid #b7bde2;color:#000080;"> <b style="font-size:15px;">Thank you,</b><br/> <b style="font-size:20px;">$5$</b> </div> </div> </div>'
        body = get_disp_value(body_html, name, message, uploaded_list_value, error_list_value, sender_name)
    elif upload_done and not is_warn:
        body_html = '<div style="background-color: #ffffff; padding-left:10%;padding-top:30px;width:645px;"> <div style="border:1px solid #ebecf7; background-color: #f3f4f7;width:100%;"> <div style="padding-left: 40px;padding-top: 20px;padding-bottom: 10px;padding-right: 10px;color:#000080;"> <b style="font-size:20px;">Dear $1$,</b> <br/><br/> <span>Your request to the bulk upload has been completed with the status [<b>$2$</b>]</span> <br/><br/> <div class="row"><div class="col-xs-12" style="display: flex;justify-content: center;"><table border="2" bordercolor="blue"><thead><tr><th>Sheet Name</th><th>No of Inserted Rows</th><th>No of Updated Rows</th><th>No of Deleted Rows</th></tr></thead><tbody>$3$</table></div></div></div> <div style="padding-left: 40px;padding-top: 15px;padding-bottom: 10px; border-top:2px solid #b7bde2;color:#000080;"> <b style="font-size:15px;">Thank you,</b><br/> <b style="font-size:20px;">$4$</b> </div> </div> </div>'
        body = get_disp_value(body_html, name, message, uploaded_list_value, sender_name)
    elif is_error:
        body_html = '<div style="background-color: #ffffff; padding-left:10%;padding-top:30px;width:645px;"> <div style="border:1px solid #ebecf7; background-color: #f3f4f7;width:100%;"> <div style="padding-left: 40px;padding-top: 20px;padding-bottom: 10px;padding-right: 10px;color:#000080;"> <b style="font-size:20px;">Dear $1$,</b> <br/><br/> <span>Your request to the bulk upload has been completed with the status [<b>$2$</b>]</span> <br/><br/> <div class="row"><div class="col-xs-12" style="display: flex;justify-content: center;"><table border="2" bordercolor="blue"><thead><tr><th>Sheet Name</th><th>Row Number</th><th>Error Type</th><th>Error Reason</th></tr></thead><tbody>$3$</table></div></div></div> <div style="padding-left: 40px;padding-top: 15px;padding-bottom: 10px; border-top:2px solid #b7bde2;color:#000080;"> <b style="font-size:15px;">Thank you,</b><br/> <b style="font-size:20px;">$4$</b> </div> </div> </div>'
        body = get_disp_value(body_html, name, message, error_list_value, sender_name)
    elif is_warn and not upload_done:
        body_html = '<div style="background-color: #ffffff; padding-left:10%;padding-top:30px;width:645px;"> <div style="border:1px solid #ebecf7; background-color: #f3f4f7;width:100%;"> <div style="padding-left: 40px;padding-top: 20px;padding-bottom: 10px;padding-right: 10px;color:#000080;"> <b style="font-size:20px;">Dear $1$,</b> <br/><br/> <span>Your request to the bulk upload has been completed with the status [<b>$2$</b>]</span> <br/><br/> <div class="row"><div class="col-xs-12" style="display: flex;justify-content: center;"><table border="2" bordercolor="blue"><thead><tr><th>Sheet Name</th><th>Row Number</th><th>Error Type</th><th>Error Reason</th></tr></thead><tbody>$3$</table></div></div></div> <div style="padding-left: 40px;padding-top: 15px;padding-bottom: 10px; border-top:2px solid #b7bde2;color:#000080;"> <b style="font-size:15px;">Cheers,</b><br/> <b style="font-size:20px;">$4$</b> </div> </div> </div>'
        body = get_disp_value(body_html, name, message, error_list_value, sender_name)
    try:
        send_email_message(from_email, [admin_user.email], None, None, subject, body)
    except Exception as e:
        logger.warn("Unable to send bulk upload status email to email id: " + admin_user.email)
        logger.warn(e)

        
class BulkUploadErrorData(object):
    def __init__(self, table, row_num, error_type, error_reason):
        self.table = table
        self.row_num = row_num
        self.error_type = error_type
        self.error_reason = error_reason


class BulkUploadCount(object):
    def __init__(self, table, no_of_inserted_rows, no_of_updated_rows, no_of_deleted_rows):
        self.table = table
        self.no_of_inserted_rows = no_of_inserted_rows
        self.no_of_updated_rows = no_of_updated_rows
        self.no_of_deleted_rows = no_of_deleted_rows


class ChangePassword(FormView):
    form_class = ChangePasswordForm
    template_name = 'change_password.html'

    def get_success_url(self):
        return reverse_lazy('common_login')

    def get_context_data(self, **kwargs):
        context = super(ChangePassword, self).get_context_data(**kwargs)
        context['current_year'] = get_current_year()
        return context

    def get(self, request, *args, **kwargs):
        password_reset_uuid = kwargs['url_id']
        try:
            adminobj = Administrator.objects.get(password_reset_uuid = password_reset_uuid)
        except ObjectDoesNotExist:
            return HttpResponseRedirect(reverse('common_requesterror'))
        return super(ChangePassword, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        password_reset_uuid = self.kwargs['url_id']
        adminobj = Administrator.objects.get(password_reset_uuid = password_reset_uuid)
        user = User.objects.get(pk = adminobj.pk)
        form = self.form_class(data = request.POST)
        if form.is_valid():
            logger.debug('Password Change Form is valid')
            password = request.POST['password']
            user.set_password(password)
            user.save()
            adminobj = Administrator.objects.get(pk = user.id)
            adminobj.password_reset_uuid = None
            adminobj.pssword_reset_uuid_create_time = None
            adminobj.save()
            logger.info('Successfully changed password for user [' + user.username + ']')
        else:
            logger.debug('Password Change Form is invalid')
            return render(request, self.template_name, {'form':form})
        return super(ChangePassword, self).post(request, args, kwargs)

@class_view_decorator(login_required)
class ListCountryVendorEmail(AdminListView):
    model = CountryVendorEmail
    template_name = 'list_country_vendor_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = CountryVendorEmail.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListCountryVendorEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListCountryVendorEmail, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateCountryVendorEmail(AdminCreateView):
    model = CountryVendorEmail
    form_class = CreateCountryVendorEmailForm
    template_name = 'create_country_vendor_email.html'
    success_message = 'New Country Client Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateCountryVendorEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        country_details = Country.objects.filter(is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['country'].queryset =  country_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateCountryVendorEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateCountryVendorEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateCountryVendorEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Country Client Email created successfully'
        return reverse('administrations:list_country_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateCountryVendorEmailDetails(AdminUpdateView):
    model = CountryVendorEmail
    form_class = UpdateCountryVendorEmailDetailForm
    template_name = 'update_country_vendor_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCountryVendorEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        countryvendoremailObj = CountryVendorEmail.objects.get(pk = self.kwargs['pk'])
        country_details = Country.objects.filter(is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['country'].queryset =  country_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['countryvendoremailObj'] = countryvendoremailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCountryVendorEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCountryVendorEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        countryVendorEmail_details = CountryVendorEmail.objects.get(pk = self.kwargs['pk'])
        kw['countryVendorEmail_details'] = countryVendorEmail_details
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateCountryVendorEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Country Client Email details sucessfully!'
        return super(UpdateCountryVendorEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_country_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class ListStateVendorEmail(AdminListView):
    model = StateVendorEmail
    template_name = 'list_state_vendor_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = StateVendorEmail.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListStateVendorEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListStateVendorEmail, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateStateVendorEmail(AdminCreateView):
    model = StateVendorEmail
    form_class = CreateStateVendorEmailForm
    template_name = 'create_state_vendor_email.html'
    success_message = 'New State Client Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateStateVendorEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        state_details = State.objects.filter(is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['state'].queryset =  state_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateStateVendorEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateStateVendorEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateStateVendorEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New State Client Email created successfully'
        return reverse('administrations:list_state_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateStateVendorEmailDetails(AdminUpdateView):
    model = StateVendorEmail
    form_class = UpdateStateVendorEmailDetailForm
    template_name = 'update_state_vendor_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateStateVendorEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        statevendoremailObj = StateVendorEmail.objects.get(pk = self.kwargs['pk'])
        state_details = State.objects.filter(is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['state'].queryset =  state_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['statevendoremailObj'] = statevendoremailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateStateVendorEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateStateVendorEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        stateVendorEmail_details = StateVendorEmail.objects.get(pk = self.kwargs['pk'])
        kw['stateVendorEmail_details'] = stateVendorEmail_details
        kw['vendor'] = self.kwargs['vendor_id']
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateStateVendorEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated State Client Email details sucessfully!'
        return super(UpdateStateVendorEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_state_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class ListRegionVendorEmail(AdminListView):
    model = RegionVendorEmail
    template_name = 'list_region_vendor_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = RegionVendorEmail.objects.filter(vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListRegionVendorEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListRegionVendorEmail, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateRegionVendorEmail(AdminCreateView):
    model = RegionVendorEmail
    form_class = CreateRegionVendorEmailForm
    template_name = 'create_region_vendor_email.html'
    success_message = 'New Region Client Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateRegionVendorEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        region_details = Region.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['region'].queryset =  region_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateRegionVendorEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateRegionVendorEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateRegionVendorEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Region Client Email created successfully'
        return reverse('administrations:list_region_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateRegionVendorEmailDetails(AdminUpdateView):
    model = RegionVendorEmail
    form_class = UpdateRegionVendorEmailDetailForm
    template_name = 'update_region_vendor_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateRegionVendorEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        regionvendoremailObj = RegionVendorEmail.objects.get(pk = self.kwargs['pk'])
        region_details = Region.objects.filter(is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['region'].queryset =  region_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['regionvendoremailObj'] = regionvendoremailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateRegionVendorEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateRegionVendorEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        regionVendorEmail_details = RegionVendorEmail.objects.get(pk = self.kwargs['pk'])
        kw['regionVendorEmail_details'] = regionVendorEmail_details
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateRegionVendorEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Region Client Email details sucessfully!'
        return super(UpdateRegionVendorEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_region_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})


@class_view_decorator(login_required)
class ListBranchVendorEmail(AdminListView):
    model = BranchVendorEmail
    template_name = 'list_branch_vendor_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = BranchVendorEmail.objects.filter(vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListBranchVendorEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListBranchVendorEmail, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateBranchVendorEmail(AdminCreateView):
    model = BranchVendorEmail
    form_class = CreateBranchVendorEmailForm
    template_name = 'create_branch_vendor_email.html'
    success_message = 'New Branch Client Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateBranchVendorEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        vendorObj = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        branch_details = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor = vendorObj).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['branch'].queryset =  branch_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateBranchVendorEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateBranchVendorEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateBranchVendorEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Branch Client Email created successfully'
        return reverse('administrations:list_branch_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateBranchVendorEmailDetails(AdminUpdateView):
    model = BranchVendorEmail
    form_class = UpdateBranchVendorEmailDetailForm
    template_name = 'update_branch_vendor_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateBranchVendorEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        branchvendoremailObj = BranchVendorEmail.objects.get(pk = self.kwargs['pk'])
        vendorObj = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        branch_details = Branch.objects.filter(tenant = adminobj.tenant, is_active = True, vendor = vendorObj).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['branch'].queryset =  branch_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['branchvendoremailObj'] = branchvendoremailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateBranchVendorEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateBranchVendorEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        branchVendorEmail_details = BranchVendorEmail.objects.get(pk = self.kwargs['pk'])
        kw['branchVendorEmail_details'] = branchVendorEmail_details
        kw['vendor'] = self.kwargs['vendor_id']
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateBranchVendorEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Branch Client Email details sucessfully!'
        return super(UpdateBranchVendorEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_branch_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})


@class_view_decorator(login_required)
class ListLocationVendorEmail(AdminListView):
    model = LocationVendorEmail
    template_name = 'list_location_vendor_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = LocationVendorEmail.objects.filter(vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListLocationVendorEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListLocationVendorEmail, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateLocationVendorEmail(AdminCreateView):
    model = LocationVendorEmail
    form_class = CreateLocationVendorEmailForm
    template_name = 'create_location_vendor_email.html'
    success_message = 'New Location Client Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateLocationVendorEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        location_details = Location.objects.filter(branch__tenant = adminobj.tenant, is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['location'].queryset =  location_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateLocationVendorEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateLocationVendorEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateLocationVendorEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Location Client Email created successfully'
        return reverse('administrations:list_location_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateLocationVendorEmailDetails(AdminUpdateView):
    model = LocationVendorEmail
    form_class = UpdateLocationVendorEmailDetailForm
    template_name = 'update_location_vendor_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLocationVendorEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        locationvendoremailObj = LocationVendorEmail.objects.get(pk = self.kwargs['pk'])
        location_details = Location.objects.filter(branch__tenant = adminobj.tenant, is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['location'].queryset =  location_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['locationvendoremailObj'] = locationvendoremailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateLocationVendorEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateLocationVendorEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        locationVendorEmail_details = LocationVendorEmail.objects.get(pk = self.kwargs['pk'])
        kw['locationVendorEmail_details'] = locationVendorEmail_details
        kw['vendor'] = self.kwargs['vendor_id']
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateLocationVendorEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Location Client Email details sucessfully!'
        return super(UpdateLocationVendorEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_location_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})


@class_view_decorator(login_required)
class ListQueueVendorEmail(AdminListView):
    model = QueueVendorEmail
    template_name = 'list_queue_vendor_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = QueueVendorEmail.objects.filter(vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListQueueVendorEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListQueueVendorEmail, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class CreateQueueVendorEmail(AdminCreateView):
    model = QueueVendorEmail
    form_class = CreateQueueVendorEmailForm
    template_name = 'create_queue_vendor_email.html'
    success_message = 'New Queue Client Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateQueueVendorEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        vendorObj = Vendor.objects.get(pk = 6)
        queue_details = Queue.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['queue'].queryset =  queue_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateQueueVendorEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateQueueVendorEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateQueueVendorEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Queue Client Email created successfully'
        return reverse('administrations:list_queue_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})


@class_view_decorator(login_required)
class UpdateQueueVendorEmailDetails(AdminUpdateView):
    model = QueueVendorEmail
    form_class = UpdateQueueVendorEmailForm
    template_name = 'update_queue_vendor_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateQueueVendorEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queuevendoremailObj = QueueVendorEmail.objects.get(pk = self.kwargs['pk'])
        vendorObj = Vendor.objects.get(pk = 6)
        queue_details = Queue.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        mailrecepienttype_details = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        context['form'].fields['queue'].queryset =  queue_details
        context['form'].fields['recepient_type'].queryset =  mailrecepienttype_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['queuevendoremailObj'] = queuevendoremailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateQueueVendorEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateQueueVendorEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        queueVendorEmail_details = QueueVendorEmail.objects.get(pk = self.kwargs['pk'])
        kw['queueVendorEmail_details'] = queueVendorEmail_details
        kw['vendor'] = self.kwargs['vendor_id']
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateQueueVendorEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Queue Client Email details sucessfully!'
        return super(UpdateQueueVendorEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_queue_vendor_email', kwargs={'vendor_id':self.kwargs['vendor_id']})


@class_view_decorator(login_required)
class ListAutoEmail(AdminListView):
    model = AutoEmail
    template_name = 'list_auto_email.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = AutoEmail.objects.filter(vendor = self.kwargs['vendor_id'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListAutoEmail,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get(self, request, *args, **kwargs):
        return super(ListAutoEmail, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateAutoEmail(AdminCreateView):
    model = AutoEmail
    form_class = CreateAutoEmailForm
    template_name = 'create_auto_email.html'
    success_message = 'New Auto Email created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateAutoEmail,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        autoemail_details = AutoEmail.objects.filter(tenant = adminobj.tenant).order_by('name')
        context['vendor_id'] = self.kwargs['vendor_id']
        vendorObj = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        callStatus_details = CallStatus.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        reasonCode_details = ReasonCode.objects.filter(call_status__tenant = adminobj.tenant, is_active = True).order_by('name')
        lineItemStatus_details = LineItemStatus.objects.filter(line_item_category__tenant = adminobj.tenant, is_active = True).order_by('name')
        customTrigger_details = CustomTrigger.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        recepient_types = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True)
        mail_recepient_list = []
        for area_type in range(1, 7):
            for recepient_type in recepient_types:
                has_data = False
                area_val = None
                if area_type == 1:
                    area_val = 'Country'
                    has_data = CountryVendorEmail.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 2:
                    area_val = 'State'
                    has_data = StateVendorEmail.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 3:
                    area_val = 'Region'
                    has_data = RegionVendorEmail.objects.filter(region__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 4:
                    area_val = 'Branch'
                    has_data = BranchVendorEmail.objects.filter(branch__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 5:
                    area_val = 'Location'
                    has_data = LocationVendorEmail.objects.filter(location__branch__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 6:
                    area_val = 'Queue'
                    has_data = QueueVendorEmail.objects.filter(queue__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                if has_data:
                    concatId = str(area_type) + '_' + str(recepient_type.id)
                    concatVal = area_val + ' - ' + recepient_type.name
                    mail_recepient_list.append([concatId, concatVal])
        context['form'].fields['to'].choices =  mail_recepient_list
        context['form'].fields['cc'].choices =  mail_recepient_list
        context['form'].fields['bcc'].choices =  mail_recepient_list
        context['form'].fields['call_status'].queryset =  callStatus_details
        context['form'].fields['reason_code'].queryset =  reasonCode_details
        context['form'].fields['line_item_status'].queryset =  lineItemStatus_details
        context['form'].fields['custom_trigger'].queryset =  customTrigger_details
        return context

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateAutoEmail,self).form_valid(form)

    def get_form_kwargs(self):
        kw = super(CreateAutoEmail, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor'] = self.kwargs['vendor_id']
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateAutoEmail, self).get(request, args, kwargs)

    def get_success_url(self):
        #form = self.form_class(data = self.request.POST)
        auto_email_obj = AutoEmail.objects.get(pk = self.object.pk)
        #if form.is_valid():
        to_list = self.request.POST.getlist('to')
        for to in to_list:
            spliVal = to.split("_")
            mailRecepientTypeobj = MailRecepientType.objects.get(pk = spliVal[1])
            autoEmailObj = AutoEmailRecepients(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 1)
            autoEmailObj.save()
        cc_list = self.request.POST.getlist('cc')
        for cc in cc_list:
            spliVal = cc.split("_")
            mailRecepientTypeobj = MailRecepientType.objects.get(pk = spliVal[1])
            autoEmailObj = AutoEmailRecepients(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 2)
            autoEmailObj.save()
        bcc_list = self.request.POST.getlist('bcc')
        for bcc in bcc_list:
            spliVal = bcc.split("_")
            mailRecepientTypeobj = MailRecepientType.objects.get(pk = spliVal[1])
            autoEmailObj = AutoEmailRecepients(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 3)
            autoEmailObj.save()
        self.success_message = 'New Auto Email created successfully'
        return reverse('administrations:list_auto_email', kwargs={'vendor_id':self.kwargs['vendor_id']})

@class_view_decorator(login_required)
class UpdateAutoEmailDetails(AdminUpdateView):
    model = AutoEmail
    form_class = UpdateAutoEmailDetailForm
    template_name = 'update_auto_email_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateAutoEmailDetails,self).get_context_data(**kwargs)
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        autoemailObj = AutoEmail.objects.get(pk = self.kwargs['pk'])
        autoemail_details = AutoEmail.objects.filter(tenant = adminobj.tenant).order_by('name')
        callStatus_details = CallStatus.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        reasonCode_details = ReasonCode.objects.filter(call_status__tenant = adminobj.tenant, is_active = True).order_by('name')
        lineItemStatus_details = LineItemStatus.objects.filter(line_item_category__tenant = adminobj.tenant, is_active = True).order_by('name')
        customTrigger_details = CustomTrigger.objects.filter(tenant = adminobj.tenant, is_active = True).order_by('name')
        recepient_types = MailRecepientType.objects.filter(tenant = adminobj.tenant, is_active = True)
        mail_recepient_list = []
        for area_type in range(1, 7):
            for recepient_type in recepient_types:
                has_data = False
                area_val = None
                if area_type == 1:
                    area_val = 'Country'
                    has_data = CountryVendorEmail.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 2:
                    area_val = 'State'
                    has_data = StateVendorEmail.objects.filter(tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 3:
                    area_val = 'Region'
                    has_data = RegionVendorEmail.objects.filter(region__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 4:
                    area_val = 'Branch'
                    has_data = BranchVendorEmail.objects.filter(branch__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 5:
                    area_val = 'Location'
                    has_data = LocationVendorEmail.objects.filter(location__branch__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()
                elif area_type == 6:
                    area_val = 'Queue'
                    has_data = QueueVendorEmail.objects.filter(queue__tenant = adminobj.tenant, vendor = self.kwargs['vendor_id'], recepient_type = recepient_type).exists()    
                if has_data:
                    concatId = str(area_type) + '_' + str(recepient_type.id)
                    concatVal = area_val + ' - ' + recepient_type.name
                    mail_recepient_list.append([concatId, concatVal])
        toList = []
        ccList = []
        bccList = []
        toObj = AutoEmailRecepients.objects.filter(auto_email = self.kwargs['pk'], recepient_position = 1)
        ccObj = AutoEmailRecepients.objects.filter(auto_email = self.kwargs['pk'], recepient_position = 2)
        bccObj = AutoEmailRecepients.objects.filter(auto_email = self.kwargs['pk'], recepient_position = 3)
        for to in toObj:
            concatId = str(to.area_type) + '_' + str(to.recepient_type.id)
            toList.append(concatId)
        for cc in ccObj:
            concatId = str(cc.area_type) + '_' + str(cc.recepient_type.id)
            ccList.append(concatId)
        for bcc in bccObj:
            concatId = str(bcc.area_type) + '_' + str(bcc.recepient_type.id)
            bccList.append(concatId)
        context['form'].fields['to'].initial = toList
        context['form'].fields['cc'].initial = ccList
        context['form'].fields['bcc'].initial = bccList
        context['form'].fields['to'].choices =  mail_recepient_list
        context['form'].fields['cc'].choices =  mail_recepient_list
        context['form'].fields['bcc'].choices =  mail_recepient_list
        context['form'].fields['call_status'].queryset =  callStatus_details
        context['form'].fields['reason_code'].queryset =  reasonCode_details
        context['form'].fields['line_item_status'].queryset =  lineItemStatus_details
        context['form'].fields['custom_trigger'].queryset =  customTrigger_details
        context['vendor_id'] = self.kwargs['vendor_id']
        context['autoemailObj'] = autoemailObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateAutoEmailDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateAutoEmailDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        autoEmail_details = AutoEmail.objects.get(pk = self.kwargs['pk'])
        kw['autoEmail_details'] = autoEmail_details
        kw['vendor'] = self.kwargs['vendor_id']
        return kw
        
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(UpdateAutoEmailDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        return super(UpdateAutoEmailDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        auto_email_obj = AutoEmail.objects.get(pk = self.kwargs['pk'])
        to_list = self.request.POST.getlist('to')
        to_list_before = AutoEmailRecepients.objects.filter(auto_email = self.kwargs['pk'], recepient_position = 1)
        for to in to_list_before:
            concatId = str(to.area_type) + '_' + str(to.recepient_type.id)
            if concatId in to_list:
                pass
            else:
                to.delete()
        for to in to_list:
            spliVal = to.split("_")
            mailRecepientTypeobj = MailRecepientType.objects.get(pk = spliVal[1])
            autoEmailObjCheck = AutoEmailRecepients.objects.filter(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 1)
            if not autoEmailObjCheck:
                autoEmailObj = AutoEmailRecepients(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 1)
                autoEmailObj.save()
        cc_list = self.request.POST.getlist('cc')
        cc_list_before = AutoEmailRecepients.objects.filter(auto_email = self.kwargs['pk'], recepient_position = 2)
        for cc in cc_list_before:
            concatId = str(cc.area_type) + '_' + str(cc.recepient_type.id)
            if concatId in cc_list:
                pass
            else:
                cc.delete()
        for cc in cc_list:
            spliVal = cc.split("_")
            mailRecepientTypeobj = MailRecepientType.objects.get(pk = spliVal[1])
            autoEmailObjCheck = AutoEmailRecepients.objects.filter(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 2)
            if not autoEmailObjCheck:
                autoEmailObj = AutoEmailRecepients(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 2)
                autoEmailObj.save()
        bcc_list = self.request.POST.getlist('bcc')
        bcc_list_before = AutoEmailRecepients.objects.filter(auto_email = self.kwargs['pk'], recepient_position = 3)
        for bcc in bcc_list_before:
            concatId = str(bcc.area_type) + '_' + str(bcc.recepient_type.id)
            if concatId in bcc_list:
                pass
            else:
                bcc.delete()
        for bcc in bcc_list:
            spliVal = bcc.split("_")
            mailRecepientTypeobj = MailRecepientType.objects.get(pk = spliVal[1])
            autoEmailObjCheck = AutoEmailRecepients.objects.filter(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 3)
            if not autoEmailObjCheck:
                autoEmailObj = AutoEmailRecepients(auto_email = auto_email_obj, recepient_type = mailRecepientTypeobj, area_type = spliVal[0], recepient_position = 3)
                autoEmailObj.save()
        self.success_message = 'Updated Auto Email details sucessfully!'
        return reverse('administrations:list_auto_email', kwargs={'vendor_id':self.kwargs['vendor_id']})


@class_view_decorator(login_required)
class ResetPassword(AdminFormView):
    form_class = ResetPasswordForm
    template_name = 'reset_password.html'
    model = Engineer

    def get_context_data(self, **kwargs):
        context = super(ResetPassword,self).get_context_data(**kwargs)
        context['engineerobj'] = Engineer.objects.get(pk = self.kwargs['pk'])
        return context

    def get_success_url(self):
        return reverse_lazy('administrations:list_engineers')

    def get(self, request, *args, **kwargs):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        if not adminobj.tenant:
            return HttpResponseRedirect(reverse('common:common_requesterror'))
        return super(ResetPassword, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        form = self.form_class(data = request.POST)
        if form.is_valid():
            logger.debug('Password Change Form is valid')
            raw_password = request.POST['password']
            engineerobj = Engineer.objects.get(pk = kwargs['pk'])
            hash_password = make_password(raw_password)
            engineerobj.password = hash_password
            engineerobj.save()
            messages.success(request, 'Password reset completed successfully')
        return super(ResetPassword, self).post(request, args, kwargs)


@class_view_decorator(login_required)
class ListAgeingCallDetails(AdminFormView):
    form_class = CallAgeingReportForm
    template_name = 'list_ageing_ticket.html'
    redirecturl = 'administrations:list_call_ageing_tickets'

    def get_context_data(self, **kwargs):
        context = super(ListAgeingCallDetails, self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        vendor_choices = []
        vendor_details = None
        if len(self.request.session['user_vendors']) == 0:
            vendor_details = list(admin_user.tenant.applicable_vendors.filter(is_active = True).order_by('name'))
        else:
            vendor_details = self.request.session['user_vendors']
        have_multiple_vendors = False
        if len(vendor_details) > 1:
            have_multiple_vendors = True
        vendor_id_list = []
        if len(vendor_details) > 0:
            for vendor in vendor_details:
                vendor_id_list.append(vendor.pk)
        context['have_multiple_vendors'] = have_multiple_vendors
        for vendor in vendor_details:
            vendor_choices.append([vendor.id, vendor.name])
        context['form'] = self.form_class(vendor_choices)
        filter_map = cache.get('call_ageing_ticket_filter_map_' + str(admin_user.pk))
        if filter_map:
            selected_vendor = filter_map['selected_vendor']
        else:
            if len(vendor_details) > 1:
                selected_vendor = '2'
            else:
                selected_vendor = vendor_details[0].pk
            filter_map = {}
            filter_map['selected_vendor'] = selected_vendor
        cache.set('call_ageing_ticket_filter_map_' + str(admin_user.pk), filter_map, 180)
        context['form'].fields['vendor'].initial = selected_vendor
        data = get_vendor_data(selected_vendor, admin_user.tenant, self.request.session['user_branch_list'])
        context['data'] = data
        context['is_post'] = True
        return context
    
    def get_success_url(self):
        return reverse_lazy(self.redirecturl)
   
    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        time_offset = pytz.timezone(request.session['DEFAULT_TIME_ZONE'])
        selected_vendor = request.POST.get('vendor')
        filter_map = {}
        filter_map['selected_vendor'] = selected_vendor
        cache.set('call_ageing_ticket_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(ListAgeingCallDetails, self).post(request, args, kwargs)


@class_view_decorator(login_required)
class ListSeverityLevel(AdminListView):
    model = SeverityLevel
    template_name = 'list_severity_level.html'

    def get_queryset(self):
        queryset = SeverityLevel.objects.filter(customer = self.kwargs['pk'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListSeverityLevel,self).get_context_data(**kwargs)
        context['customer_id'] = self.kwargs['pk']
        return context

@class_view_decorator(login_required)
class CreateSeverityLevel(AdminCreateView):
    model = SeverityLevel
    form_class = CreateSeverityLevelForm
    template_name = 'create_severity_level.html'
    success_message = 'New Severity Level created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateSeverityLevel,self).get_context_data(**kwargs)
        context['customerObj'] = Customer.objects.get(pk = self.kwargs['customer_id'])
        return context

    def get_form_kwargs(self):
        kw = super(CreateSeverityLevel, self).get_form_kwargs()
        kw['customer'] = self.kwargs['customer_id']
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.customer = Customer.objects.get(pk = self.kwargs['customer_id'])
        return super(CreateSeverityLevel,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '1'
        return super(CreateSeverityLevel, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Severity Level created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.kwargs['customer_id']})

    
@class_view_decorator(login_required)
class UpdateSeverityLevelDetails(AdminUpdateView):
    model = SeverityLevel
    form_class = UpdateSeverityLevelDetailForm
    template_name = 'update_severity_level_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSeverityLevelDetails,self).get_context_data(**kwargs)
        severitylevelObj = SeverityLevel.objects.get(pk = self.kwargs['pk'])
        context['severityLevelObj'] = severitylevelObj
        context['customer_id'] = severitylevelObj.customer.pk
        if severitylevelObj.has_severity_level_sla():
            context['form'].fields['is_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA applicable already exist with Severity Level, so you won\'t be able to uncheck this checkbox'}
        return context

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '1'
        return super(UpdateSeverityLevelDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateSeverityLevelDetails, self).get_form_kwargs()
        severity_level_details = SeverityLevel.objects.get(pk = self.kwargs['pk'])
        kw['severity_level_details'] = severity_level_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Severity Level details sucessfully!'
        return super(UpdateSeverityLevelDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        severity_level_details = SeverityLevel.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_customer', kwargs={'pk':severity_level_details.customer.pk})


@class_view_decorator(login_required)
class ListTier(AdminListView):
    model = Tier
    template_name = 'list_tier.html'

    def get_queryset(self):
        queryset = Tier.objects.filter(customer = self.kwargs['pk'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListTier,self).get_context_data(**kwargs)
        context['customer_id'] = self.kwargs['pk']
        return context

@class_view_decorator(login_required)
class CreateTier(AdminCreateView):
    model = Tier
    form_class = CreateTierForm
    template_name = 'create_tier.html'
    success_message = 'New Tier created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateTier,self).get_context_data(**kwargs)
        context['customerObj'] = Customer.objects.get(pk = self.kwargs['customer_id'])
        return context

    def get_form_kwargs(self):
        kw = super(CreateTier, self).get_form_kwargs()
        kw['customer'] = self.kwargs['customer_id']
        return kw

    def form_valid(self, form):
        form.instance.customer = Customer.objects.get(pk = self.kwargs['customer_id'])
        return super(CreateTier,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '2'
        return super(CreateTier, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Tier created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.kwargs['customer_id']})

    
@class_view_decorator(login_required)
class UpdateTierDetails(AdminUpdateView):
    model = Tier
    form_class = UpdateTierDetailForm
    template_name = 'update_tier_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateTierDetails,self).get_context_data(**kwargs)
        tierObj = Tier.objects.get(pk = self.kwargs['pk'])
        context['tierObj'] = tierObj
        context['customer_id'] = tierObj.customer.pk
        if tierObj.has_tier_sla():
            context['form'].fields['is_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA applicable already exist with Tier, so you won\'t be able to uncheck this checkbox'}
        return context

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '2'
        return super(UpdateTierDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateTierDetails, self).get_form_kwargs()
        tier_details = Tier.objects.get(pk = self.kwargs['pk'])
        kw['tier_details'] = tier_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Tier details sucessfully!'
        return super(UpdateTierDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        tier_details = Tier.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_customer', kwargs={'pk':tier_details.customer.pk})


@class_view_decorator(login_required)
class ListHoliday(AdminListView):
    model = Holiday
    template_name = 'list_holiday.html'

    def get_queryset(self):
        queryset = Holiday.objects.filter(customer = self.kwargs['pk'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListHoliday,self).get_context_data(**kwargs)
        context['customer_id'] = self.kwargs['pk']
        return context

@class_view_decorator(login_required)
class CreateHoliday(AdminCreateView):
    model = Holiday
    form_class = CreateHolidayForm
    template_name = 'create_holiday.html'
    success_message = 'New Holiday created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateHoliday,self).get_context_data(**kwargs)
        context['customerObj'] = Customer.objects.get(pk = self.kwargs['customer_id'])
        return context

    def get_form_kwargs(self):
        kw = super(CreateHoliday, self).get_form_kwargs()
        kw['customer'] = self.kwargs['customer_id']
        return kw

    def form_valid(self, form):
        form.instance.customer = Customer.objects.get(pk = self.kwargs['customer_id'])
        return super(CreateHoliday,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '5'
        return super(CreateHoliday, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Holiday created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.kwargs['customer_id']})

    
@class_view_decorator(login_required)
class UpdateHolidayDetails(AdminUpdateView):
    model = Holiday
    form_class = UpdateHolidayDetailForm
    template_name = 'update_holiday_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateHolidayDetails,self).get_context_data(**kwargs)
        holidayObj = Holiday.objects.get(pk = self.kwargs['pk'])
        context['holidayObj'] = holidayObj
        context['customer_id'] = holidayObj.customer.pk
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateHolidayDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateHolidayDetails, self).get_form_kwargs()
        holiday_details = Holiday.objects.get(pk = self.kwargs['pk'])
        kw['holiday_details'] = holiday_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Holiday details sucessfully!'
        return super(UpdateHolidayDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        holiday_details = Holiday.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_customer', kwargs={'pk':holiday_details.customer.pk})


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class DeleteHolidayDate(View):

    def post(self, request, *args, **kwargs):
        response_xml = '<ok/>'
        try:
            date_id = self.kwargs['pk']
            holiday_date_record = Holiday.objects.get(pk = date_id)
            holiday_date_record.delete()
        except:
            body = traceback.format_exc()
            logger.error(body)
            response_xml = '<nok/>'
        return HttpResponse(response_xml, content_type='text/xml')


@class_view_decorator(login_required)
class ListSLA(AdminListView):
    model = SLA
    template_name = 'list_sla.html'

    def get_queryset(self):
        queryset = SLA.objects.filter(customer = self.kwargs['pk'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListSLA,self).get_context_data(**kwargs)
        context['customer_id'] = self.kwargs['pk']
        return context

@class_view_decorator(login_required)
class CreateSLA(AdminCreateView):
    model = SLA
    form_class = CreateSLAForm
    template_name = 'create_sla.html'
    success_message = 'New SLA created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateSLA,self).get_context_data(**kwargs)
        customer_details = Customer.objects.get(pk = self.kwargs['customer_id'])
        severity_level_list = SeverityLevel.objects.filter(customer=self.kwargs['customer_id'], is_sla_applicable = True)
        tier_list = Tier.objects.filter(customer=self.kwargs['customer_id'], is_sla_applicable = True)
        department_list = Department.objects.filter(customer=self.kwargs['customer_id'], is_sla_applicable = True)
        location_type_list = LocationType.objects.filter(customer=self.kwargs['customer_id'], is_sla_applicable = True)
        context['customer_id'] = self.kwargs['customer_id']
        context['customer_details'] = customer_details
        context['form'].fields['severity_level'].queryset =  severity_level_list
        context['form'].fields['tier'].queryset =  tier_list
        context['form'].fields['department'].queryset =  department_list
        context['form'].fields['location_type'].queryset =  location_type_list
        return context

    def get_form_kwargs(self):
        kw = super(CreateSLA, self).get_form_kwargs()
        customer_details = Customer.objects.get(pk = self.kwargs['customer_id'])
        kw['customer'] = self.kwargs['customer_id']
        kw['customer_details'] = customer_details
        return kw

    def form_valid(self, form):
        form.instance.customer = Customer.objects.get(pk = self.kwargs['customer_id'])
        return super(CreateSLA,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '6'
        return super(CreateSLA, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New SLA created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.kwargs['customer_id']})

    
@class_view_decorator(login_required)
class UpdateSLADetails(AdminUpdateView):
    model = SLA
    form_class = UpdateSLADetailForm
    template_name = 'update_sla_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSLADetails,self).get_context_data(**kwargs)
        slaObj = SLA.objects.get(pk = self.kwargs['pk'])
        customer_details = Customer.objects.get(pk = slaObj.customer.pk)
        severity_level_list = SeverityLevel.objects.filter(customer=slaObj.customer.pk, is_sla_applicable = True)
        tier_list = Tier.objects.filter(customer=slaObj.customer.pk, is_sla_applicable = True)
        department_list = Department.objects.filter(customer=slaObj.customer.pk, is_sla_applicable = True)
        location_type_list = LocationType.objects.filter(customer=slaObj.customer.pk, is_sla_applicable = True)
        context['slaObj'] = slaObj
        context['customer_id'] = slaObj.customer.pk
        context['customer_details'] = customer_details
        return context

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '6'
        return super(UpdateSLADetails, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated SLA details sucessfully!'
        return super(UpdateSLADetails, self).post(request, args, kwargs)

    def get_success_url(self):
        sla_details = SLA.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_customer', kwargs={'pk':sla_details.customer.pk})


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class DeleteSLA(View):

    def post(self, request, *args, **kwargs):
        request.session['active_tab'] = '6'
        response_xml = '<ok/>'
        try:
            sla_id = self.kwargs['pk']
            sla_record = SLA.objects.get(pk = sla_id)
            sla_record.delete()
        except:
            body = traceback.format_exc()
            logger.error(body)
            response_xml = '<nok/>'
        return HttpResponse(response_xml, content_type='text/xml')



@class_view_decorator(login_required)
class ListDepartment(AdminListView):
    model = Department
    #template_name = 'list_department.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Department.objects.filter(customer = self.kwargs['pk'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListDepartment,self).get_context_data(**kwargs)
        context['customer_id'] = self.kwargs['pk']
        return context


@class_view_decorator(login_required)
class CreateDepartment(AdminCreateView):
    model = Department
    form_class = CreateDepartmentForm
    template_name = 'create_department.html'
    success_message = 'New Department created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateDepartment,self).get_context_data(**kwargs)
        context['customerObj'] = Customer.objects.get(pk = self.kwargs['customer_id'])
        return context

    def get_form_kwargs(self):
        kw = super(CreateDepartment, self).get_form_kwargs()
        kw['customer'] = self.kwargs['customer_id']
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.customer = Customer.objects.get(pk = self.kwargs['customer_id'])
        return super(CreateDepartment,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '3'
        return super(CreateDepartment, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Department created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.kwargs['customer_id']})

@class_view_decorator(login_required)
class UpdateDepartmentDetails(AdminUpdateView):
    model = Department
    form_class = UpdateDepartmentDetailsForm
    template_name = 'update_department_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateDepartmentDetails,self).get_context_data(**kwargs)
        departmentObj = Department.objects.get(pk = self.kwargs['pk'])
        if departmentObj.has_department_sla():
            context['form'].fields['is_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA applicable already exist with Department, so you won\'t be able to uncheck this checkbox'}
        context['departmentObj'] = departmentObj
        return context

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '3'
        return super(UpdateDepartmentDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateDepartmentDetails, self).get_form_kwargs()
        department_details = Department.objects.get(pk = self.kwargs['pk'])
        kw['department_details'] = department_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Department details sucessfully!'
        return super(UpdateDepartmentDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        department_details = Department.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_customer', kwargs={'pk':department_details.customer.pk})

@class_view_decorator(login_required)
class ListLocationType(AdminListView):
    model = LocationType
    template_name = 'list_location_type.html'

    def get_queryset(self):
        queryset = LocationType.objects.filter(customer = self.kwargs['pk'])
        return queryset

    def get_context_data(self, **kwargs):
        context = super(ListLocationType,self).get_context_data(**kwargs)
        context['customer_id'] = self.kwargs['pk']
        return context

@class_view_decorator(login_required)
class CreateLocationType(AdminCreateView):
    model = LocationType
    form_class = CreateLocationTypeForm
    template_name = 'create_location_type.html'
    success_message = 'New Location type created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateLocationType,self).get_context_data(**kwargs)
        context['customerObj'] = Customer.objects.get(pk = self.kwargs['customer_id'])
        return context

    def get_form_kwargs(self):
        kw = super(CreateLocationType, self).get_form_kwargs()
        kw['customer'] = self.kwargs['customer_id']
        return kw

    def form_valid(self, form):
        form.instance.customer = Customer.objects.get(pk = self.kwargs['customer_id'])
        return super(CreateLocationType,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '4'
        return super(CreateLocationType, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Location type created successfully'
        return reverse('administrations:update_customer', kwargs={'pk':self.kwargs['customer_id']})

@class_view_decorator(login_required)
class UpdateLocationTypeDetails(AdminUpdateView):
    model = LocationType
    form_class = UpdateLocationTypeDetailsForm
    template_name = 'update_location_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLocationTypeDetails,self).get_context_data(**kwargs)
        locationtypeObj = LocationType.objects.get(pk = self.kwargs['pk'])
        context['locationTypeObj'] = locationtypeObj
        if locationtypeObj.has_location_type_sla():
            context['form'].fields['is_sla_applicable'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'SLA applicable already exist with Location Type, so you won\'t be able to uncheck this checkbox'}
        return context

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '4'
        return super(UpdateLocationTypeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateLocationTypeDetails, self).get_form_kwargs()
        location_type_details = LocationType.objects.get(pk = self.kwargs['pk'])
        kw['location_type_details'] = location_type_details
        return kw

    def post(self, request, *args, **kwargs):
        self.success_message = 'Updated Location type details sucessfully!'
        return super(UpdateLocationTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        location_type_details = LocationType.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_customer', kwargs={'pk':location_type_details.customer.pk})


@class_view_decorator(login_required)
class ListVendorSupport(AdminListView):
    model = VendorSupport
    template_name = 'list_vendor_support.html'

    def get_queryset(self):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        queryset = VendorSupport.objects.filter(tenant = adminobj.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListVendorSupport, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateVendorSupport(AdminCreateView):
    model = VendorSupport
    form_class = CreateVendorSupportForm
    template_name = 'create_vendor_support.html'

    def get_context_data(self, **kwargs):
        context = super(CreateVendorSupport,self).get_context_data(**kwargs)
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateVendorSupport, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        vendor_support_list = []
        vendor_spoc_contact_number_list = []
        vendor_support_details = VendorSupport.objects.filter(tenant = admin_user.tenant)
        for vendor in vendor_support_details :
            vendor_support_list.append(vendor.get_vendor_name_address_value())
            vendor_spoc_contact_number_list.append(vendor.spoc_contact_number)
        kw['tenant'] = admin_user.tenant
        kw['vendor_support_list'] = vendor_support_list
        kw['vendor_spoc_contact_number_list'] = vendor_spoc_contact_number_list
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.spoc_contact_number = validate_mobile_countryCode(self.request.POST.get('spoc_contact_number'))
        return super(CreateVendorSupport,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateVendorSupport, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Vendor Support created successfully'
        return reverse('administrations:list_vendor_support')

@class_view_decorator(login_required)
class UpdateVendorSupportDetails(AdminUpdateView):
    model = VendorSupport
    form_class = UpdateVendorSupportDetailForm
    template_name = 'update_vendor_support_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateVendorSupportDetails,self).get_context_data(**kwargs)
        vendorsupportObj = VendorSupport.objects.get(pk = self.kwargs['pk'])
        context['vendorsupportObj'] = vendorsupportObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateVendorSupportDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateVendorSupportDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        vendor_support_list = []
        vendor_spoc_contact_number_list = []
        vendor_list = VendorSupport.objects.filter(tenant = admin_user.tenant)
        for vendor in vendor_list :
            vendor_support_list.append(vendor.get_vendor_name_address_value())
            vendor_spoc_contact_number_list.append(vendor.spoc_contact_number)
        kw['vendor_support_list'] = vendor_support_list
        kw['vendor_spoc_contact_number_list'] = vendor_spoc_contact_number_list
        vendor_support_details = VendorSupport.objects.get(pk = self.kwargs['pk'])
        kw['vendor_support_details'] = vendor_support_details
        return kw
    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.spoc_contact_number = validate_mobile_countryCode(self.request.POST.get('spoc_contact_number'))
        return super(UpdateVendorSupportDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        vendorsupportObj = VendorSupport.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Vendor Support details sucessfully!'
        return super(UpdateVendorSupportDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_vendor_support')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class MyProfile(AdminFormView):
    form_class = ProfileForm
    template_name = 'my_profile.html'
    success_message = 'Profile updated sucessfully!'

    def get_context_data(self, **kwargs):
        context = super(MyProfile,self).get_context_data(**kwargs)
        user = Administrator.objects.get(pk = self.request.user.id)
        context['form'].fields['first_name'].initial = user.first_name
        context['form'].fields['last_name'].initial = user.last_name
        return context

    def get_success_url(self):
        return reverse_lazy('administrations:my_profile')

    def post(self, request, *args, **kwargs):
        form = self.form_class(data = request.POST)
        if form.is_valid():
            logger.debug('My Profile Form is valid')
            user = Administrator.objects.get(pk = request.user.id)
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            user.first_name = first_name
            user.last_name = last_name
            user.save()
        else:
            logger.debug('My Profile Form is invalid')
            #return render(request, self.template_name, {'form':form})
        return super(MyProfile, self).post(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class ResetMyPassword(FormView):
    form_class = ChangePasswordForm
    template_name = 'reset_my_password.html'
    redirect_url = 'common_logout'

    def get_success_url(self):
        return reverse_lazy(redirect_url)

    def post(self, request, *args, **kwargs):
        user = Administrator.objects.get(pk = request.user.id)
        form = self.form_class(data = request.POST, user = user)
        if form.is_valid():
            logger.debug('Password Reset Form is valid')
            password = request.POST['password']
            user.set_password(password)
            user.password_reset_uuid = None
            user.pssword_reset_uuid_create_time = None
            user.reset_password_on_next_login = False
            user.save()
            messages.success(request, 'Your password has been reset successfully. Please login with your new password.')
            return HttpResponseRedirect(reverse_lazy(self.redirect_url))
        else:
            logger.debug('Password Reset Form is invalid')
            return render(request, self.template_name, {'form':form})
        return super(ResetMyPassword, self).post(request, args, kwargs)


@class_view_decorator(csrf_exempt)
class GetUnreadNotifications(View):

    def post(self, request, *args, **kwargs):
        response_str = '<response>'
        try:
            if self.request.user.is_authenticated:
                update_user_heart_beat(self.request.user)
                response_str += '<status>OK</status>'
                response_str += '<unread_notification_count>'
                response_str += str(get_unread_notification_list_response_html(self.request.user)[0])
                response_str += '</unread_notification_count>'                
                response_str += '<unread_notification_string>'
                response_str += '<![CDATA[' + get_unread_notification_list_response_html(self.request.user)[1] + ']]>'
                response_str += '</unread_notification_string>'                
            else:
                response_str += '<status>NOK</status>'    
        except:
            response_str += '<status>NOK</status>'
        response_str += '</response>' 
        return HttpResponse(response_str, content_type='text/xml')


def update_user_heart_beat(userobj):

    logger.debug('Updating heartbeat of user [' + userobj.username + ']')
    userobj = HCMSUser.objects.filter(user_ptr_id = userobj.id).first()
    if userobj:
        userobj.last_heartbeat = timezone.now()
        userobj.save()
        logger.debug('Updated heartbeat of user [' + userobj.username + ']')


def get_unread_notification_list_response_html(userobj):
    
    # receiverobj = HCMSUser.objects.get(pk = userobj.pk)
    # get_unread_notifications_for_user(receiverobj)
    unread_notification_list = cache.get('unread_notification_'+str(userobj.pk), [])
    unread_notification_count = 0
    if unread_notification_list:
        unread_notification_count = unread_notification_list.count()
    unread_notification_response_string = ''
    for unreadnotification in unread_notification_list:
        get_formatted_notification_created_time(unreadnotification)
        #unread_notification_response_string += '<div class="vertical-timeline-item vertical-timeline-element"><div><span class="vertical-timeline-element-icon"><i class="badge badge-dot badge-dot-xl badge-success"> </i></span><div class="vertical-timeline-element-content"><h4 class="timeline-title">' + unreadnotification.title + '</h4><p class="more">' + unreadnotification.message + '</p></div><span  style="position: absolute; top: 3px; right: 0px; font-size: 10px; color: #aaa;">'+ unreadnotification.time_elapsed +'</span></div></div>'
        unread_notification_response_string += '<div class="vertical-timeline-item vertical-timeline-element"><div><span class="vertical-timeline-element-icon"><i class="badge badge-dot badge-dot-xl badge-success"> </i></span><div class="vertical-timeline-element-content"><h4 class="timeline-title">' + unreadnotification.title + '</h4></div><span  style="position: absolute; top: 3px; right: 0px; font-size: 10px; color: #aaa;">'+ unreadnotification.time_elapsed +'</span></div></div>'
    return [unread_notification_count, unread_notification_response_string]


def notification_post_save_signal_receiver(sender, **kwargs):
    notificationobj = kwargs['instance']
    get_unread_notifications_for_user(notificationobj.receiver)

post_save.connect(notification_post_save_signal_receiver, sender = Notification)


def get_formatted_notification_created_time(notification):

        tz_info = notification.created_time.tzinfo
        time_elapsed_minutes = (datetime.now(tz_info) - notification.created_time).total_seconds() / 60
        if time_elapsed_minutes < 2:
            notification.time_elapsed = 'Just Now'
        elif time_elapsed_minutes < 60:
            notification.time_elapsed = str(int(time_elapsed_minutes)) + ' min(s) ago'
        elif time_elapsed_minutes < 1440:
            notification.time_elapsed = str(int(time_elapsed_minutes / 60))  + ' hour(s) ago'
        elif time_elapsed_minutes < 10080:
            notification.time_elapsed = str(int(time_elapsed_minutes / 1440)) + ' day(s) ago'
        else:
            notification.time_elapsed = 'older'   


def get_unread_notifications_for_user(receiverobj):

    time_offset = pytz.timezone('Asia/Kolkata')
    today = datetime.now(time_offset)
    start_date = datetime(year = today.year, month = today.month, day = 1, tzinfo = time_offset)
    end_date = start_date + relativedelta(months = 1)
    last_month_start_date = start_date + relativedelta(months = -1)
    last_month_end_date = end_date + relativedelta(months = -1)
    unread_notification_list = Notification.objects.filter(receiver = receiverobj, created_time__gte = last_month_start_date, is_read = False).order_by('-created_time')
    key = 'unread_notification_' + str(receiverobj.pk)
    cache.set(key, unread_notification_list, None)


@class_view_decorator(login_required)
class ShowNotifications(AdminTemplateView):
    template_name = 'show_notifications.html'

    def get_context_data(self, **kwargs):
        context = super(ShowNotifications, self).get_context_data(**kwargs)
        receiverobj = HCMSUser.objects.get(pk = self.request.user.pk)
        time_offset = pytz.timezone('Asia/Kolkata')
        today = datetime.now(time_offset)
        start_date = datetime(year = today.year, month = today.month, day = 1, tzinfo = time_offset)
        last_month_start_date = start_date + relativedelta(months = -1)        
        all_notifications = Notification.objects.filter(receiver = receiverobj, created_time__gte = last_month_start_date).order_by('-created_time')
        context['all_notifications'] = all_notifications
        return context

    def get(self, request, *args, **kwargs):
        return super(ShowNotifications, self).get(request, args, kwargs)
    

@class_view_decorator(login_required)
class MarkAsReadUnread(View):

    def get(self, request, *args, **kwargs):
        output_xml = '<read/>'
        try:
            notification_id = int(kwargs['notification_id'])
            # update corresponding object
            notificationobj = Notification.objects.get(id = notification_id)
            if notificationobj.is_read:
                notificationobj.is_read = False
                logger.debug('Notification Marked as Unread')
                output_xml = '<unread/>'
            else:
                notificationobj.is_read = True
                logger.debug('Notification Marked as Read')
            notificationobj.save()
        except Exception as e:
            logger.exception("Something went wrong, please try after sometime")
            output_xml = '<nok/>'
        return HttpResponse(output_xml, content_type='text/xml')


@class_view_decorator(login_required)
class MarkAllAsRead(View):

    def get(self, request, *args, **kwargs):
        output_xml = '<ok/>'
        try:
            notification_list = Notification.objects.filter(receiver_id = request.user.id)
            for notificationobj in notification_list:
                if not notificationobj.is_read:
                    notificationobj.is_read = True
                    notificationobj.save()
        except Exception as e:
            logger.exception("Something went wrong, please try after sometime")
            output_xml = '<nok/>'
        return HttpResponse(output_xml, content_type='text/xml')
        

@class_view_decorator(login_required)
class ListEngineerReport(AdminFormView):
    form_class = EngineerReportForm
    template_name = 'list_engineer_report.html'
    redirecturl = 'administrations:list_engineer_report'

    def get_context_data(self, **kwargs):
        context = super(ListEngineerReport, self).get_context_data(**kwargs)
        context['report_type'] = self.kwargs['report_type']
        vendor_id_list = []
        branch_id_list = []
        engineer_list = []
        vendor_choices = []
        branch_choices = []
        engineer_choices = []
        vendor_branch_map = {}
        vendor_branch_engineer_map = {}
        common_vendor_engineer_list = []
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        common_vendor_details = Vendor.objects.all().order_by('name')
        common_branch_details = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('vendor')
        common_engineer_details = Engineer.objects.filter(tenant = admin_user.tenant).order_by('technician_id').order_by('first_name')
        user_vendor_list = self.request.session.get('user_vendors')
        user_branch_list = self.request.session.get('user_branches')
        common_vendor_engineer_details = Engineer.objects.filter(vendors__isnull = True)
        common_branch_engineer_details = Engineer.objects.filter(access_branches__isnull = True)
        engineer_list.append(common_vendor_engineer_details)
        for common_vendor_engineer in common_vendor_engineer_details:
            common_vendor_engineer_list.append(common_vendor_engineer.pk)
        if len(user_vendor_list) > 0: 
            for vendor in user_vendor_list:
                vendor_id_list.append(vendor.pk)
            for branch in user_branch_list:
                branch_id_list.append(branch.pk)
            common_branch_details = common_branch_details.filter(vendor__id__in = vendor_id_list)
            common_vendor_details = common_vendor_details.filter(pk__in = vendor_id_list)
        if len(vendor_id_list) > 0 or len(branch_id_list) > 0:
            common_engineer_details = common_engineer_details.filter(Q(vendors__id__in = vendor_id_list)|Q(access_branches__id__in = branch_id_list)).distinct()
            engineer_list.append(common_engineer_details)
        else:
            engineer_list.append(common_engineer_details)
        if len(vendor_id_list) > 1 or len(vendor_id_list) == 0:
            vendor_choices.append([-1, 'All'])
        if len(branch_id_list) > 1 or len(branch_id_list) == 0:
            branch_choices.append([-1, 'All'])
        if len(common_engineer_details) > 0:
            engineer_choices.append([-1, 'All'])
        for common_vendor in common_vendor_details:
            vendor_choices.append([common_vendor.pk, common_vendor.name])
        for common_branch in common_branch_details:
            branch_choices.append([common_branch.pk, common_branch.name + '-' + common_branch.vendor.name])
        engineer_map = {}
        for engineer_details in engineer_list:
            for engineer in engineer_details:
                if not engineer_map.get(engineer.pk):
                    engineer_choices.append([engineer.pk, engineer.first_name + ' - ' + engineer.technician_id])
                    engineer_map[engineer.pk] = True
        time_offset = pytz.timezone(self.request.session['DEFAULT_TIME_ZONE'])
        start_date = timezone.now() + timedelta(-7)
        to_date = timezone.now()
        from_date = "{:%Y%m%d}".format(start_date)
        to_date = "{:%Y%m%d}".format(to_date)
        fdate = datetime.strptime(from_date,"%Y%m%d").date()
        tdate = datetime.strptime(to_date,"%Y%m%d").date()
        fdatestr = datetime(fdate.year, fdate.month, fdate.day)
        tdatestr = datetime(tdate.year, tdate.month, tdate.day)
        fdtstr = fdatestr.strftime("%Y-%m-%d")
        tdtstr = tdatestr.strftime("%Y-%m-%d")
        daterangeval = fdtstr + str(" - ") + tdtstr
        start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
        end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
        end_date = end_date + relativedelta(days = 1)
        context['form'].fields['vendor'].choices = vendor_choices
        context['form'].fields['branch'].choices = branch_choices
        context['form'].fields['engineer'].choices = engineer_choices
        context['form'].fields['daterange'].initial = daterangeval
        filter_map = cache.get('engineer_report_filter_map_' + str(admin_user.pk))
        if filter_map:
            selected_vendor = filter_map['selected_vendor']
            selected_branch = filter_map['selected_branch']
            selected_engineer = filter_map['selected_engineer']
            start_date = filter_map['start_date']
            end_date = filter_map['end_date']
            daterangeval = filter_map['daterangeval']
            context['form'].fields['vendor'].initial = selected_vendor
            context['form'].fields['branch'].initial = selected_branch
            context['form'].fields['engineer'].initial = selected_engineer
            context['form'].fields['daterange'].initial = daterangeval
        else:
            if len(common_vendor_details) > 1:
                selected_vendor = '-1'
            else:
                selected_vendor = common_vendor_details[0].pk
            if len(common_branch_details) > 1:
                selected_branch = '-1'
            else:
                selected_branch = common_branch_details[0].pk
            selected_engineer = '-1'
        cache.set('engineer_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        engineer_report_details = get_engineer_report(selected_vendor, selected_branch, selected_engineer, common_vendor_engineer_list, admin_user.tenant, start_date, end_date, vendor_id_list, branch_id_list, self.kwargs['report_type'], time_offset)
        context['engineer_report_details'] = engineer_report_details[0]
        return context

    def get(self, request, *args, **kwargs):
        return super(ListEngineerReport, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)

    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        time_offset = pytz.timezone(request.session['DEFAULT_TIME_ZONE'])
        selected_vendor = request.POST.get('vendor')
        selected_branch = request.POST.get('branch')
        selected_engineer = request.POST.get('engineer')
        daterangeval = request.POST.get('daterange')
        split_set = daterangeval.split(' - ')
        from_date = split_set[0]
        to_date = split_set[1]
        fdate = datetime.strptime(from_date,"%Y-%m-%d").date()
        tdate = datetime.strptime(to_date,"%Y-%m-%d").date()
        start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
        end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
        end_date = end_date + relativedelta(days = 1)
        filter_map = {}
        filter_map['selected_vendor'] = selected_vendor
        filter_map['selected_branch'] = selected_branch
        filter_map['selected_engineer'] = selected_engineer
        filter_map['start_date'] = start_date
        filter_map['end_date'] = end_date
        filter_map['daterangeval'] = daterangeval
        cache.set('engineer_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(ListEngineerReport, self).post(request, args, kwargs)


@class_view_decorator(login_required)
class UserLoginReport(AdminFormView):
    form_class = LoginReportForm
    template_name = 'user_lastlogin_report.html'
    redirecturl = 'administrations:user_login_report'
    
    def get_context_data(self, **kwargs):
        context = super(UserLoginReport, self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        users_choices = []
        users = HCMSUser.objects.all()
        users_choices.append([-1, 'All'])
        users_choices.append([1, 'Web Users'])
        users_choices.append([2, 'Engineers'])
        context['form'].fields['user'].choices = users_choices
        filter_map = cache.get('lastlogin_report_filter_map_' + str(admin_user.pk))
        time_offset = pytz.timezone(self.request.session['DEFAULT_TIME_ZONE'])
        if filter_map:
            selected_user = filter_map['selected_user']
            start_date = filter_map['start_date']
            end_date = filter_map['end_date']
            daterangeval = filter_map['daterangeval']
            context['form'].fields['user'].initial = selected_user
            context['form'].fields['daterange'].initial = daterangeval
        else:
            selected_user = '-1'
            start_date = timezone.now() - timedelta(days = 7)
            end_date = timezone.now()
            from_date = "{:%Y%m%d}".format(start_date)
            end_date = "{:%Y%m%d}".format(end_date)
            fdate = datetime.strptime(from_date,"%Y%m%d").date()
            tdate = datetime.strptime(end_date,"%Y%m%d").date()
            fdatestr = datetime(fdate.year, fdate.month, fdate.day)
            tdatestr = datetime(tdate.year, tdate.month, tdate.day)
            fdtstr = fdatestr.strftime("%Y-%m-%d")
            tdtstr = tdatestr.strftime("%Y-%m-%d")
            daterangeval = fdtstr + str(" - ") + tdtstr
            start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
            end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
            #end_date = end_date + timedelta(days = 1)
            context['form'].fields['daterange'].initial = daterangeval
        last_login_data = []
        end_date = end_date + timedelta(days = 1)
        if selected_user == '-1':
            last_login_data = HCMSUser.objects.filter(last_login__range = [start_date, end_date], tenant = admin_user.tenant)
        if selected_user == '1':
            last_login_data = Administrator.objects.filter(last_login__range = [start_date, end_date], tenant = admin_user.tenant)
        if selected_user == '2':
            last_login_data = Engineer.objects.filter(last_login__range = [start_date, end_date], tenant = admin_user.tenant)
        cache.set('lastlogin_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        context['last_login_data'] = last_login_data
        return context
        
    def get(self, request, *args, **kwargs):
        return super(UserLoginReport, self).get(request, args, kwargs)
        
    def get_success_url(self):
        return reverse_lazy(self.redirecturl)
    
    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        time_offset = pytz.timezone(request.session['DEFAULT_TIME_ZONE'])
        selected_user = request.POST.get('user')
        daterangeval = request.POST.get('daterange')
        split_set = daterangeval.split(' - ')
        from_date = split_set[0]
        to_date = split_set[1]
        fdate = datetime.strptime(from_date,"%Y-%m-%d").date()
        tdate = datetime.strptime(to_date,"%Y-%m-%d").date()
        start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
        end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
        filter_map = {}
        filter_map['selected_user'] = selected_user
        filter_map['start_date'] = start_date
        filter_map['end_date'] = end_date
        filter_map['daterangeval'] = daterangeval
        cache.set('lastlogin_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(UserLoginReport, self).post(request, args, kwargs)
    

@class_view_decorator(login_required)
class ActiveUsersReport(AdminFormView):
    form_class = ActiveUsersReportForm
    template_name = 'active_users_report.html'
    redirecturl = 'administrations:active_users_report'
    
    def get_context_data(self, **kwargs):
        context = super(ActiveUsersReport, self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        users_choices = []
        users = HCMSUser.objects.all()
        users_choices.append([-1, 'All'])
        users_choices.append([1, 'Web Users'])
        users_choices.append([2, 'Engineers'])
        context['form'].fields['user'].choices = users_choices
        filter_map = cache.get('active_users_filter_map_' + str(admin_user.pk))
        time_offset = pytz.timezone(self.request.session['DEFAULT_TIME_ZONE'])
        if filter_map:
            selected_user = filter_map['selected_user']
            start_date = filter_map['start_date']
            end_date = filter_map['end_date']
            daterangeval = filter_map['daterangeval']
            context['form'].fields['user'].initial = selected_user
            context['form'].fields['daterange'].initial = daterangeval
        else:
            selected_user = '-1'
            start_date = timezone.now() - timedelta(days = 7)
            end_date = timezone.now()
            from_date = "{:%Y%m%d}".format(start_date)
            end_date = "{:%Y%m%d}".format(end_date)
            fdate = datetime.strptime(from_date,"%Y%m%d").date()
            tdate = datetime.strptime(end_date,"%Y%m%d").date()
            fdatestr = datetime(fdate.year, fdate.month, fdate.day)
            tdatestr = datetime(tdate.year, tdate.month, tdate.day)
            fdtstr = fdatestr.strftime("%Y-%m-%d")
            tdtstr = tdatestr.strftime("%Y-%m-%d")
            daterangeval = fdtstr + str(" - ") + tdtstr
            start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
            end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
            #end_date = end_date + timedelta(days = 1)
            context['form'].fields['daterange'].initial = daterangeval
        active_users_data = []
        end_date = end_date + timedelta(days = 1)
        if selected_user == '-1':
            active_users_data = HCMSUser.objects.filter(last_login__range = [start_date, end_date], tenant = admin_user.tenant, is_logged_in = 't')
        if selected_user == '1':
            active_users_data = Administrator.objects.filter(last_login__range = [start_date, end_date], tenant = admin_user.tenant, is_logged_in = 't')
        if selected_user == '2':
            active_users_data = Engineer.objects.filter(last_login__range = [start_date, end_date], tenant = admin_user.tenant, is_logged_in = 't')
        cache.set('active_users_filter_map_' + str(admin_user.pk), filter_map, 180)
        context['active_users_data'] = active_users_data
        return context
        
    def get(self, request, *args, **kwargs):
        return super(ActiveUsersReport, self).get(request, args, kwargs)
        
    def get_success_url(self):
        return reverse_lazy(self.redirecturl)
    
    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        time_offset = pytz.timezone(request.session['DEFAULT_TIME_ZONE'])
        selected_user = request.POST.get('user')
        daterangeval = request.POST.get('daterange')
        split_set = daterangeval.split(' - ')
        from_date = split_set[0]
        to_date = split_set[1]
        fdate = datetime.strptime(from_date,"%Y-%m-%d").date()
        tdate = datetime.strptime(to_date,"%Y-%m-%d").date()
        start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
        end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
        filter_map = {}
        filter_map['selected_user'] = selected_user
        filter_map['start_date'] = start_date
        filter_map['end_date'] = end_date
        filter_map['daterangeval'] = daterangeval
        cache.set('active_users_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(ActiveUsersReport, self).post(request, args, kwargs)
    

@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class AutoAssignEngineer(View):

    def post(self, request, *args, **kwargs):
        self.success_message = 'Engineer Assigned successfully!'
        response_str = '<response>'
        try:
            branch = request.POST['branch']
            client = request.POST['client']
            call_id = request.POST['call_id']
            appointment_date_component_str = request.POST['appointment_date']
            appointment_time_component_str = request.POST['appointment_time']
            appointment_date_component = parser.parse(appointment_date_component_str)
            appointment_time_component = convert_time_str_to_time_arr(appointment_time_component_str)
            appointment_time = datetime(year = appointment_date_component.year, month = appointment_date_component.month, day = appointment_date_component.day, hour = appointment_time_component[0], minute = appointment_time_component[1], tzinfo = timezone.utc)
            appointment_time -= timedelta(minutes = 330)
            vendorobj = Vendor.objects.get(name = str(client))
            callticketobj = CallTicket.objects.get(pk = call_id)
            if callticketobj.customer and callticketobj.customer.location:
                engineerslist = Engineer.objects.filter(Q(access_branches = branch)|Q(access_branches = None),Q(vendors = vendorobj.pk)|Q(vendors = None), Q(access_locations = callticketobj.customer.location)|Q(access_locations = None))
            else:
                engineerslist = Engineer.objects.filter(Q(access_branches = branch)|Q(access_branches = None),Q(vendors = vendorobj.pk)|Q(vendors = None))
            if callticketobj.is_auto_appointment:
                time_offset = pytz.timezone('Asia/Kolkata')
                today_date = datetime.now()
                today_date_time = today_date.replace(tzinfo=time_offset)
                today_date_time += timedelta(minutes = 330)
                working_time_end_in_minutes = callticketobj.customer.working_end_time
                today_end = str(timedelta(minutes=working_time_end_in_minutes))
                today_end =str(today_date.date()) +' '+ str(today_end)
                today_end = datetime.strptime(today_end, '%Y-%m-%d %H:%M:%S')
                today_end = today_end.replace(tzinfo=time_offset)
                earliest_engineer_available = []
                for engineer in engineerslist:
                    available_time = get_engineers_latest_available_time(callticketobj, engineer, today_date_time, today_end)
                    available_time = available_time
                    engineer.earliest_available_time = available_time
                    engineer.save()
                engineer_sorted_by_earliest_available_time = sorted(engineerslist, key=operator.attrgetter('earliest_available_time'))
                latest_available = engineer_sorted_by_earliest_available_time[0]
                if latest_available:
                    callticketobj.appointment_time = latest_available.earliest_available_time
                    callticketobj.save()
                    epk = latest_available.pk
            else:
                epk = get_auto_assign_engineer_id(engineerslist, callticketobj,appointment_time)
            response_str += '<status>OK</status>'
            response_str += '<engineer_id>'+str(epk)+'</engineer_id>'
        except:
            response_str += '<status>NOK</status>'
        response_str += '</response>'
        return HttpResponse(response_str, content_type='text/xml')
    
@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class RecallEngineer(View):

    def post(self, request, *args, **kwargs):
        self.success_message = 'Engineer Recalled successfully!'
        response_str = '<response>'
        audit_json = []
        try:
            updated_time = timezone.now()
            admin_user = Administrator.objects.get(pk=self.request.user.id)
            user = HCMSUser.objects.get(pk=self.request.user.id)
            ticket_id = self.kwargs['pk']
            callticket_obj = CallTicket.objects.get(pk = ticket_id)
            curr_call_engineer = callticket_obj.assigned_engineer
            old_assigned_engineer = str(callticket_obj.assigned_engineer.first_name)
            old_is_auto_assigned = callticket_obj.is_auto_assigned
            old_auto_assigned_status = callticket_obj.get_auto_assigned_status_display()
            callticket_obj.assigned_engineer = None
            callticket_obj.is_auto_assigned = False
            assignedengineertracking = AssignedEngineerTrack(engineer = curr_call_engineer, ticket = callticket_obj, appointment_time = callticket_obj.appointment_time, modified_by = admin_user, assigned_status = callticket_obj.ASSIGNED_STATUS_RECALLED)
            assignedengineertracking.save()
            callticket_obj.auto_assigned_status = callticket_obj.ASSIGNED_STATUS_RECALLED
            callticket_obj.save()
            new_auto_assigned_status = callticket_obj.get_auto_assigned_status_display()
            audit_json.append({"table_name":"CallTicket", "pk":callticket_obj.pk, "display_name":"Assigned Engineer", "field_name":"assigned_engineer", "old_value":old_assigned_engineer, "new_value":None})
            audit_json.append({"table_name":"CallTicket", "pk":callticket_obj.pk, "display_name":"Auto Assigned Flag", "field_name":"is_auto_assigned", "old_value":old_is_auto_assigned, "new_value":False})
            audit_json.append({"table_name":"CallTicket", "pk":callticket_obj.pk, "display_name":"Auto Assigned Status", "field_name":"auto_assigned_status", "old_value":old_auto_assigned_status, "new_value":new_auto_assigned_status})
            change_audit = TicketChangesAudit(ticket = callticket_obj, audit_json = json.dumps(audit_json), updated_by = user, updated_time = updated_time)
            change_audit.save()
            response_str += '<status>OK</status>'
        except:
            response_str += '<status>NOK</status>'
        response_str += '</response>'
        return HttpResponse(response_str, content_type='text/xml')


@class_view_decorator(login_required)
class ListCallClassification(AdminListView):
    model = CallClassification
    template_name = 'list_call_classification.html'

    def get_context_data(self, **kwargs):
        context = super(ListCallClassification,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = CallClassification.objects.filter(tenant = admin_user.tenant, vendor = self.kwargs['vendor_id'])
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListCallClassification, self).get(request, args, kwargs)
    
@class_view_decorator(login_required)
class DisplayCallClassificationDetails(AdminTemplateView):
    template_name = 'display_call_classification_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayCallClassificationDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        callclassification_details = CallType.objects.get(pk = kwargs['pk'])
        self.callclassification_details = callclassification_details
        return super(DisplayCallClassificationDetails, self).get(request, args, kwargs)
    
@class_view_decorator(login_required)
class CreateCallClassification(AdminCreateView):
    model = CallClassification
    form_class = CreateCallClassificationForm
    template_name = 'create_call_classification.html'
    success_message = 'New Call Classification created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateCallClassification,self).get_context_data(**kwargs)
        context['vendor_id'] = self.kwargs['vendor_id']
        return context
        
    def get_form_kwargs(self):
        kw = super(CreateCallClassification, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['vendor_id'] = self.kwargs['vendor_id']
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = self.kwargs['vendor_id'])
        return super(CreateCallClassification,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCallClassification, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Call Classification  created successfully'
        return reverse('administrations:list_call_classification', kwargs={'vendor_id':self.kwargs['vendor_id']})
    
@class_view_decorator(login_required)
class UpdateCallClassificationDetails(AdminUpdateView):
    model = CallClassification
    form_class = UpdateCallClassificationForm
    template_name = 'update_call_classification_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCallClassificationDetails,self).get_context_data(**kwargs)
        callclassificationObj = CallClassification.objects.get(pk = self.kwargs['pk'])
        context['callclassificationObj'] = callclassificationObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCallClassificationDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCallClassificationDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        callclassification_details = CallClassification.objects.get(pk = self.kwargs['pk'])
        kw['callclassification_details'] = callclassification_details
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        callclassification_details = CallClassification.objects.get(pk = self.kwargs['pk'])
        form.instance.tenant = adminobj.tenant
        form.instance.vendor = Vendor.objects.get(pk = callclassification_details.vendor.pk)
        return super(UpdateCallClassificationDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        callclassificationObj = CallClassification.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Call Classification details sucessfully!'
        return super(UpdateCallClassificationDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        callclassification_details = CallClassification.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:list_call_classification', kwargs={'vendor_id':callclassification_details.vendor.pk})


@class_view_decorator(login_required)
class GetOpenTicketData(AdminTemplateView):
    template_name = 'get_open_ticket_list.html'

    def get_context_data(self, **kwargs):
        context = super(GetOpenTicketData,self).get_context_data(**kwargs)
        app_user = HCMSUser.objects.get(pk = self.request.user.pk)
        branch_id = int(self.kwargs['branch_id'])
        customer_id = int(self.kwargs['customer_id'])
        vendor_id = int(self.kwargs['vendor_id'])
        queue_id = int(self.kwargs['queue_id'])
        customer_group_id = int(self.kwargs['customer_group_id'])
        user_vendors = self.request.session['user_vendors']
        user_branches = self.request.session['user_branches']
        user_queues = self.request.session['user_queues']
        call_list = get_open_ticket_list(app_user, vendor_id, branch_id, customer_id, user_vendors, user_branches, queue_id, user_queues, customer_group_id)
        context['call_list'] = call_list
        context['hide_sidebar'] = True
        return context
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '4'
        return super(GetOpenTicketData, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class GetAssetData(AdminTemplateView):
    template_name = 'get_asset_list.html'

    def get_context_data(self, **kwargs):
        context = super(GetAssetData,self).get_context_data(**kwargs)
        app_user = HCMSUser.objects.get(pk = self.request.user.pk)
        branch_id = int(self.kwargs['branch_id'])
        customer_id = int(self.kwargs['customer_id'])
        vendor_id = int(self.kwargs['vendor_id'])
        customer_group_id = int(self.kwargs['customer_group_id'])
        user_vendors = self.request.session['user_vendors']
        user_branches = self.request.session['user_branches']
        asset_list = get_asset_data_list(app_user, vendor_id, branch_id, customer_id, user_vendors, user_branches, customer_group_id)
        context['asset_list'] = asset_list
        context['hide_sidebar'] = True
        return context
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '4'
        return super(GetAssetData, self).get(request, args, kwargs)

#def call_ticket_post_save_signal_receiver(sender, **kwargs):
#    if kwargs['created']:
#        callobj = kwargs['instance']
#        ProcessAlertForCallTicketsThread(callobj).start()
#    else:
#        pass
    
#post_save.connect(call_ticket_post_save_signal_receiver, sender = CallTicket)
    
class ProcessAlertForCallTicketsThread(threading.Thread):

    def __init__(self, callobj):
        self.callobj = callobj
        super(ProcessAlertForCallTicketsThread, self).__init__()

    def run(self):
        process_alert_for_call_tickets(self.callobj)
        
def process_alert_for_call_tickets(callobj):
    if callobj.customer and callobj.is_auto_appointment:
        engineerslist = Engineer.objects.filter(Q(access_branches = callobj.branch)|Q(access_branches = None),Q(vendors = callobj.vendor.pk)|Q(vendors = None), Q(access_locations = callobj.customer.location) | Q(access_locations__isnull = True))
        time_offset = timezone.utc
        today_date_time = timezone.now()
        working_time_end_in_minutes = callobj.customer.working_end_time
        today_end = str(timedelta(minutes=working_time_end_in_minutes))
        today_end =str(today_date_time.date()) +' '+ str(today_end)
        today_end = datetime.strptime(today_end, '%Y-%m-%d %H:%M:%S')
        today_end = today_end.replace(tzinfo=time_offset)
        today_end = today_end - timedelta(minutes = 330)
        earliest_engineer_available = []
        for engineer in engineerslist:
            available_time = get_engineers_latest_available_time(callobj, engineer, today_date_time, today_end)
            engineer.earliest_available_time = available_time
            engineer.save()
        engineer_sorted_by_earliest_available_time = sorted(engineerslist, key=operator.attrgetter('earliest_available_time'))
        if engineer_sorted_by_earliest_available_time:
            latest_available = engineer_sorted_by_earliest_available_time[0]
            if latest_available:
                autoassign_callstatus = CallStatus.objects.get(id = 2, tenant = callobj.tenant, name = 'Accepted')
                callstatus = CallStatus.objects.get(id = 3, tenant = callobj.tenant, name = 'In Progress')
                callreasoncode = ReasonCode.objects.get(id = 3, name = 'Technician Assigned')
                old_status = callobj.status.name
                callobj.appointment_time = latest_available.earliest_available_time
                callobj.status = callstatus
                callobj.reason_code = callreasoncode
                callobj.is_auto_assigned = True
                callobj.is_auto_appointment = True
                audit_json = []
                callobj.auto_assigned_status = callobj.ASSIGNED_STATUS_ASSIGNED
                callobj.save()
                status_track = TicketStatusTrack(ticket = callobj, new_status = autoassign_callstatus, notes = 'Engineer Auto Assigned', status_change_time = timezone.now())
                status_track.save()
                status_track = TicketStatusTrack(ticket = callobj, new_status = callobj.status, notes = 'Engineer Auto Assigned', status_change_time = timezone.now())
                status_track.save()
                if_next_engineer_available_job(callobj, latest_available.pk, None)
            else:
                process_alert_emails_for_callobj(callobj, False)

def assigned_engineer_track_post_save_signal_receiver(sender, **kwargs):
    aetobj = kwargs['instance']
    ProcessAlertForAssignedEngineerTracksThread(aetobj).start()

post_save.connect(assigned_engineer_track_post_save_signal_receiver, sender = AssignedEngineerTrack)

class ProcessAlertForAssignedEngineerTracksThread(threading.Thread):

    def __init__(self, aetobj):
        self.aetobj = aetobj
        super(ProcessAlertForAssignedEngineerTracksThread, self).__init__()

    def run(self):
        process_alert_for_assigned_engineer_tracks(self.aetobj)

def process_alert_for_assigned_engineer_tracks(aetobj):
    if aetobj.is_help_desk_notificed:
        return
    admin_users_with_call_edit_access = get_admin_users_with_edit_call_access_for_a_call(aetobj.ticket)
    if len(admin_users_with_call_edit_access) > 0:
        so_num = aetobj.ticket.get_so_num()
        from_email = settings.EMAIL_FROM
        notification_required = False
        email_required = False
        email_subject = ''
        email_body = ''
        email_call_details = get_table_formatted_call_details(aetobj.ticket)
        for calladmin in admin_users_with_call_edit_access:
            if aetobj.assigned_status == aetobj.ticket.ASSIGNED_STATUS_REJECTED:
                email_subject = 'SO#' + so_num +' rejected by engineer' 
                email_body = '<html><body>Dear ' + str(calladmin) + ',<br/><br/>The assigned ticket with SO# ' + so_num +' was rejected by an engineer('+ str(aetobj.engineer) +').<br/><br/>It will be re-assigned to another engineer by auto assignation process shortly<br/><br/>'+ email_call_details +'<br/><br/>Thank you,<br/>Hi Tech Team</body></html>'
                notification_required = True
                email_required = True
            elif aetobj.assigned_status == aetobj.ticket.ASSIGNED_STATUS_ASSIGNED:
                email_subject = 'Call with SO#' + so_num + ' is Assigned'
                email_body = '<html><body>Dear ' + str(calladmin) + ',<br/><br/>The ticket with SO# ' + so_num +' is assigned to an engineer('+ str(aetobj.engineer) +').<br/><br/>'+ email_call_details +'<br/><br/>Thank you,<br/>Hi Tech Team</body></html>'
                notification_required = False
                email_required = False
            elif aetobj.assigned_status == aetobj.ticket.ASSIGNED_STATUS_ACCEPTED:
                email_subject = 'Call with SO#' + so_num + ' is Accepted'
                email_body = '<html><body>Dear ' + str(calladmin) + ',<br/><br/>The assigned ticket with SO# ' + so_num +' is accepted by an engineer('+ str(aetobj.engineer) +').<br/><br/>'+ email_call_details +'<br/><br/>Thank you,<br/>Hi Tech Team</body></html>'
                notification_required = True
                email_required = True
            elif aetobj.assigned_status == aetobj.ticket.ASSIGNED_STATUS_NO_RESPONSE:
                email_subject = 'SO#' + so_num +' re-assigned to another engineer' 
                email_body = '<html><body>Dear ' + str(calladmin) + ',<br/><br/>Ticket with SO# ' + so_num +' is pending with the engineer('+ str(aetobj.engineer) +') for more than 15 minutes.<br/><br/>It will be re-assigned to another engineer by auto assignation process shortly<br/><br/>'+ email_call_details +'<br/><br/>Thank you,<br/>Hi Tech Team</body></html>'
                notification_required = False
                email_required = False
            elif aetobj.assigned_status == aetobj.ticket.ASSIGNED_STATUS_RECALLED:
                email_subject = 'SO#' + so_num + ' is Recalled'
                email_body = '<html><body>Dear ' + str(calladmin) + ',<br/><br/>Ticket with SO# ' + so_num +' is recalled.<br/><br/>'+ email_call_details +'<br/><br/>Thank you,<br/>Hi Tech Team</body></html>'
                notification_required = False
                email_required = False
            try:
                if email_required:
                    send_email_message(from_email, [calladmin.email], None, None, email_subject, email_body)
                if notification_required:
                    create_notification([calladmin], email_subject, email_body, None, 'Auto Assign')
            except Exception as e:
                logger.exception("Unable to send the invite SMS")
                logger.exception(e)
        if notification_required and email_required:
            aetobj.is_help_desk_notificed = True
            aetobj.save()
        if aetobj.assigned_status == aetobj.ticket.ASSIGNED_STATUS_REJECTED:
            reassign_new_engineer_after_rejection(aetobj.ticket)


@class_view_decorator(login_required)
class ListOpenTicketDependencyReport(AdminFormView):
    form_class = OpenTicketDependencyReportForm
    template_name = 'list_open_ticket_dependency_report.html'
    redirecturl = 'administrations:list_open_ticket_dependency_report'

    def get_context_data(self, **kwargs):
        context = super(ListOpenTicketDependencyReport, self).get_context_data(**kwargs)
        vendor_id_list = []
        vendor_choices = []
        dependency_report_details =  None
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        common_vendor_details = Vendor.objects.all().order_by('name')
        user_vendor_list = self.request.session.get('user_vendors')
        if len(user_vendor_list) > 0: 
            for vendor in user_vendor_list:
                vendor_id_list.append(vendor.pk)
            common_vendor_details = common_vendor_details.filter(pk__in = vendor_id_list)
        for common_vendor in common_vendor_details:
            vendor_choices.append([common_vendor.pk, common_vendor.name])
        context['form'].fields['vendor'].choices = vendor_choices
        filter_map = cache.get('dependency_report_filter_map_' + str(admin_user.pk))
        if filter_map:
            selected_vendor = filter_map['selected_vendor']
        else:
            if len(common_vendor_details) > 1:
                selected_vendor = '2'
            else:
                selected_vendor = common_vendor_details[0].pk
        cache.set('dependency_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        context['form'].fields['vendor'].initial = selected_vendor
        dependency_report_details = get_open_ticket_dependency_report(selected_vendor, admin_user.tenant)
        context['dependency_report_details'] = dependency_report_details
        return context

    def get(self, request, *args, **kwargs):
        return super(ListOpenTicketDependencyReport, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy(self.redirecturl)

    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        selected_vendor = request.POST.get('vendor')
        filter_map = {}
        filter_map['selected_vendor'] = selected_vendor
        cache.set('dependency_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(ListOpenTicketDependencyReport, self).post(request, args, kwargs)

    
@class_view_decorator(login_required)
class ListCallStatusAssignedEngineerTrack(AdminListView):
    model = AssignedEngineerTrack
    template_name = 'call_status_assigned_engineer_tracking_list.html'

    def get_context_data(self, **kwargs):
        context = super(ListCallStatusAssignedEngineerTrack,self).get_context_data(**kwargs)
        callobj = CallTicket.objects.get(pk = self.kwargs['ticket_id'])
        context['callobj'] = callobj
        #created_time = callobj.get_created_time()
        call_status_assign_engineer_track_list = AssignedEngineerTrack.objects.filter(ticket = callobj).order_by('-modified_time')
        #context['created_time'] = created_time
        context['call_status_assign_engineer_track_list'] = call_status_assign_engineer_track_list
        return context
    
@class_view_decorator(login_required)
class ListQueue(AdminListView):
    model = Queue
    template_name = 'list_queue.html'

    def get_context_data(self, **kwargs):
        context = super(ListQueue,self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Queue.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListQueue, self).get(request, args, kwargs)


@class_view_decorator(login_required)
class CreateQueue(AdminCreateView):
    model = Queue
    form_class = CreateQueueForm
    template_name = 'create_queue.html'
    success_message = 'New Queue created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateQueue,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateQueue, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateQueue,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateQueue, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Queue created successfully'
        return reverse('administrations:list_queue')


@class_view_decorator(login_required)
class UpdateQueueDetails(AdminUpdateView):
    model = Queue
    form_class = UpdateQueueDetailsForm
    template_name = 'update_queue_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateQueueDetails,self).get_context_data(**kwargs)
        queueObj = Queue.objects.get(pk = self.kwargs['pk'])
        context['queueObj'] = queueObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateQueueDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateQueueDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        queue_details = Queue.objects.get(pk = self.kwargs['pk'])
        kw['queue_details'] = queue_details
        return kw

    def post(self, request, *args, **kwargs):
        queueObj = Queue.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Queue details sucessfully!'
        return super(UpdateQueueDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_queue')


@class_view_decorator(login_required)
class CreateCallTicketServiceDesk(AdminCreateView):
    model = CallTicket
    form_class = CreateCallTicketServiceDeskForm
    template_name = 'create_call_ticket_service_desk.html'

    def get_context_data(self, **kwargs):
        context = super(CreateCallTicketServiceDesk,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        branch_list = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        machine_list  = Machine.objects.filter(branch__in = branch_list).order_by('serial_number')
        branch_choices = []
        branch_choices.append([-1, '--------------'])
        for branch in branch_list:
            branch_choices.append([branch.id, branch.get_branch_vendor_value()])
        machine_choices = []
        machine_choices.append([-1, '--------------'])
        for machine in machine_list:
            machine_choices.append([machine.id, machine])
        branch_machine_map = {}
        branch_machine_map['-1'] = machine_list
        if branch_list:
            for branch in branch_list:
                machinelist = Machine.objects.filter(branch = branch)
                branch_machine_map[branch.pk]= list(machinelist)
        queue_list = Queue.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        queue_choices = []
        queue_choices.append([-1, '--------------'])
        for queue in queue_list:
            queue_choices.append([queue.id, queue.name])
        context['form'].fields['queue'].choices = queue_choices
        vendor_list = []
        vendor_choices = []
        for vendor in self.request.session['user_vendors']:
            vendor_list.append(vendor)
            vendor_choices.append([vendor.id, vendor.name])
        context['form'].fields['vendor'].choices =  vendor_choices       
        if len(vendor_choices) == 1:
            context['form'].fields['vendor'].initial = vendor_choices[0]
        vendor_sla_list_map = {}
        for vendor in vendor_list:
            severity_level_list_vendor = []
            severity_label_vendor= 'Severity'
            tenantvendormappingobj = TenantVendorMapping.objects.filter(vendor = vendor, tenant = admin_user.tenant).first()
            if tenantvendormappingobj.severity_based_sla_applicable:
                severity_level_list_vendor= SeverityLevel.objects.filter(is_active = True, vendor = vendor).order_by('name')
                if tenantvendormappingobj.severity_name:
                    severity_label_vendor = tenantvendormappingobj.severity_name
            tier_list_vendor = []
            tier_label_vendor= 'Tier'
            if tenantvendormappingobj.tier_based_sla_applicable:
                tier_list_vendor= Tier.objects.filter(is_active = True, vendor = vendor).order_by('name')
                if tenantvendormappingobj.tier_name:
                    tier_label_vendor = tenantvendormappingobj.tier_name
            department_list_vendor = Department.objects.none()
            department_label_vendor= 'Department'
            if tenantvendormappingobj.department_based_sla_applicable:
                department_list_vendor= Department.objects.filter(is_active = True, vendor = vendor).order_by('name')
                if tenantvendormappingobj.department_name:
                    department_label_vendor = tenantvendormappingobj.department_name
            location_type_list_vendor = LocationType.objects.none()
            location_type_label_vendor= 'Location Type'
            if tenantvendormappingobj.location_type_based_sla_applicable:
                location_type_list_vendor= LocationType.objects.filter(is_active = True, vendor = vendor).order_by('name')
                if tenantvendormappingobj.location_type_name:
                    location_type_label_vendor = tenantvendormappingobj.location_type_name
            vendor_sla_list_map[vendor.id] = [list(severity_level_list_vendor), severity_label_vendor, list(tier_list_vendor), tier_label_vendor, list(department_list_vendor), department_label_vendor, list(location_type_list_vendor), location_type_label_vendor]
        context['vendor_sla_list_map'] = vendor_sla_list_map
        context['form'].fields['branch'].choices =  branch_choices
        context['form'].fields['machine'].choices =  machine_choices
        context['branch_machine_map'] = branch_machine_map
        return context        

    def get_form_kwargs(self):
        kw = super(CreateCallTicketServiceDesk, self).get_form_kwargs()
        return kw

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk = self.request.user.id)
        form.instance.vendor_id = 6
        callstatusobj = CallStatus.objects.filter(tenant = admin_user.tenant, is_initial_status = True).first()
        if callstatusobj:
            form.instance.status = callstatusobj
        form.instance.tenant_id = admin_user.tenant.id
        end_user_name = self.request.POST.get('end_user_name')
        end_user_email = self.request.POST.get('end_user_email')
        form.instance.vendor_crm_ticket_time = timezone.now()
        if end_user_name and end_user_email:
            form.instance.customer_name =  end_user_name
            form.instance.customer_email = end_user_email
            form.instance.customer_address = 'N/A'        
        tickettypeobj = TicketType.objects.filter(tenant = admin_user.tenant, is_initial_status = True).first()
        if tickettypeobj:
            form.instance.ticket_type = tickettypeobj
        return super(CreateCallTicketServiceDesk,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        self.machine = request.POST.get('machine')
        self.success_message = 'Call Ticket created sucessfully!'
        return super(CreateCallTicketServiceDesk, self).post(request, args, kwargs)

    def get_success_url(self):
        callobj = CallTicket.objects.get(pk = self.object.pk)
        updating_user = HCMSUser.objects.get(pk = self.request.user.pk)
        status_track = TicketStatusTrack(ticket = callobj, new_status = callobj.status, notes = 'New Ticket Created', status_changed_by = updating_user, status_change_time = callobj.created_time)
        status_track.save()
        if self.machine:
            machineobj = Machine.objects.filter(pk = self.machine).first()
            if machineobj:
                ticket_machine = TicketMachineDetails(serial_number = machineobj.serial_number, mtm_number = machineobj.mtm_number, warranty_type = machineobj.warranty_type, warranty_details = machineobj.warranty_details, amc_start_date = machineobj.amc_start_date, amc_end_date = machineobj.amc_end_date, hard_disk_retention = machineobj.hard_disk_retention, accident_damage_cover = machineobj.accident_damage_cover,  customer_induced_damage = machineobj.customer_induced_damage, cru_machine = machineobj.cru_machine, assest_id = machineobj.assest_id, user_name = machineobj.user_name, user_employee_id = machineobj.user_employee_id, user_designation = machineobj.user_designation, location = machineobj.location, floor = machineobj.floor, building_name = machineobj.building_name, reporting_manager_email = machineobj.reporting_manager_email, processor_speed = machineobj.processor_speed, monitor_make = machineobj.monitor_make, monitor_size = machineobj.monitor_size, host_name = machineobj.host_name, mac_address = machineobj.mac_address, ip_address = machineobj.ip_address, anti_virus_name = machineobj.anti_virus_name, anti_virus_serial_number = machineobj.anti_virus_serial_number, anti_virus_key = machineobj.anti_virus_key, anti_virus_expiry_date = machineobj.anti_virus_expiry_date, operating_system = machineobj.operating_system, ram_type = machineobj.ram_type, hard_disk_type = machineobj.hard_disk_type, softwares = machineobj.softwares, ticket_id = self.object.pk)
                if machineobj.model:
                    ticket_machine.custom_machine_type = machineobj.model.machine_type.name
                    ticket_machine.custom_make = machineobj.model.machine_make.name
                    ticket_machine.custom_model = machineobj.model.name
                ticket_machine.save()
        return reverse('administrations:display_call_ticket_details', kwargs={'pk':self.object.pk})


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class ActionPickUp(View):

    def post(self, request, *args, **kwargs):
        response_xml = '<ok/>'
        try:
            admin_user = Administrator.objects.get(pk = self.request.user.id)
            callticket_id = self.kwargs['pk']
            engineer_obj = Engineer.objects.filter(pk = admin_user.pk).first()
            callobj = CallTicket.objects.get(pk = callticket_id)
            callobj.assigned_engineer = engineer_obj
            callStatusObj = CallStatus.objects.filter(name='Accepted', tenant = admin_user.tenant).first()
            old_value = 'Blank'
            if callobj.status:
                old_value = callobj.status.name
            callobj.status = callStatusObj
            callobj.save()
            audit_json = []
            new_value = 'Blank'
            if callobj.status:
                new_value = callobj.status.name
            audit_json.append({"table_name":"CallTicket", "pk":callobj.pk, "display_name":"Call Status", "field_name":"status", "old_value":old_value, "new_value":new_value})
            change_audit = TicketChangesAudit(ticket = callobj, audit_json = json.dumps(audit_json), updated_by = engineer_obj, updated_time = timezone.now())
            change_audit.save()
            ticketStatusTrackObj = TicketStatusTrack(ticket = callobj, notes ='Self Assigned', new_status = callStatusObj, status_changed_by = engineer_obj, status_change_time = timezone.now())
            ticketStatusTrackObj.save()
            
        except:
            body = traceback.format_exc()
            logger.error(body)
            response_xml = '<nok/>'
        return HttpResponse(response_xml, content_type='text/xml')


class ListCustomerGroup(AdminListView):
    model = CustomerGroup
    template_name = 'list_customer_group.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = CustomerGroup.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListCustomerGroup, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateCustomerGroup(AdminCreateView):
    model = CustomerGroup
    form_class = CreateCustomerGroupForm
    template_name = 'create_customer_group.html'
    success_message = 'New CustomerGroup created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateCustomerGroup,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateCustomerGroup, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateCustomerGroup,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateCustomerGroup, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New CustomerGroup created successfully'
        return reverse('administrations:list_customer_group')

@class_view_decorator(login_required)
class UpdateCustomerGroupDetails(AdminUpdateView):
    model = CustomerGroup
    form_class = UpdateCustomerGroupDetailForm
    template_name = 'update_customer_group_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCustomerGroupDetails,self).get_context_data(**kwargs)
        customergroupObj = CustomerGroup.objects.get(pk = self.kwargs['pk'])
        context['customergroupObj'] = customergroupObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateCustomerGroupDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateCustomerGroupDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        customergroup_details = CustomerGroup.objects.get(pk = self.kwargs['pk'])
        kw['customergroup_details'] = customergroup_details
        return kw

    def post(self, request, *args, **kwargs):
        customergroupObj = CustomerGroup.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated CustomerGroup details sucessfully!'
        return super(UpdateCustomerGroupDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_customer_group')


@class_view_decorator(login_required)
class ListStatusTrackingReport(AdminFormView):
    form_class = StatusTrackingReportForm
    template_name = 'list_status_tracking_report.html'
    redirecturl = 'administrations:list_status_tracking_report'
    
    def get_context_data(self, **kwargs):
        context = super(ListStatusTrackingReport, self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        engineer_obj = Engineer.objects.filter(pk = admin_user.pk).first()
        is_engineer = False
        if engineer_obj:
            is_engineer = True
        context['is_engineer'] = is_engineer 
        config_map = self.request.config_map
        status_details = CallStatus.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('rank')
        queue_list = Queue.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
        customer_details = Customer.objects.filter(branch__tenant = admin_user.tenant).order_by('name')
        reason_code_details = ReasonCode.objects.filter(call_status__tenant = admin_user.tenant, is_active = True).order_by('rank')
        status_reasoncode_map = {}
        status_reasoncode_map[-1] = list(reason_code_details)
        for statusobj in status_details:
            status_reasoncode_list = ReasonCode.objects.filter(call_status = statusobj, is_active = True).order_by('rank')
            status_reasoncode_map[statusobj.id] = list(status_reasoncode_list)
        context['status_reasoncode_map'] = status_reasoncode_map
        vendor_choices = []
        vendor_details = None
        if len(self.request.session['user_vendors']) == 0:
            vendor_details = list(admin_user.tenant.applicable_vendors.filter(is_active = True).order_by('name'))
        else:
            vendor_details = self.request.session['user_vendors']
        have_multiple_vendors = False
        if len(vendor_details) > 1:
            vendor_choices.append([-1, 'All'])
            have_multiple_vendors = True
        vendor_id_list = []
        if len(vendor_details) > 0:
            for vendor in vendor_details:
                vendor_id_list.append(vendor.pk)
        context['have_multiple_vendors'] = have_multiple_vendors
        for vendor in vendor_details:
            vendor_choices.append([vendor.id, vendor.name])
        branch_id_list = []
        if len(self.request.session['user_branches']) > 0:
            for obj in self.request.session['user_branches']:
                branch_id_list.append(obj.pk)
        branch_choices = []
        branch_details = None
        if len(self.request.session['user_branches']) == 0:
            branch_details = Branch.objects.filter(tenant = admin_user.tenant, is_active = True).order_by('name')
            if len(vendor_id_list) > 0:
                branch_details = branch_details.filter(vendor__id__in = vendor_id_list)
        else:
            if len(vendor_id_list) > 0:
                branch_details =  Branch.objects.filter(Q(vendor__id__in = vendor_id_list)|Q(pk__in = branch_id_list), tenant = admin_user.tenant, is_active = True).order_by('name')
            else:  
                branch_details = self.request.session['user_branches']
        have_multiple_branches = False
        if len(branch_details) > 1:
            branch_choices.append([-1, 'All'])
            have_multiple_branches = True
        context['have_multiple_branches'] = have_multiple_branches
        for branch in branch_details:
            branch_choices.append([branch.id, branch.get_branch_vendor_value()])
        status_choices = []
        for status in status_details:
            status_choices.append([status.id, status.name])
        reason_code_choices = []
        reason_code_choices.append([-1, 'All'])
        for reason_code in reason_code_details:
            reason_code_choices.append([reason_code.id, reason_code.name])
        customer_choices = []
        customer_id_list = []
        customer_details = None
        if len(self.request.session['user_customers']) > 0:
            customer_details = self.request.session['user_customers']
        have_multiple_customers = False
        if customer_details and len(customer_details) > 1:
            customer_choices.append([-1,'All' ])
            have_multiple_customers = True
        context['have_multiple_customers'] = have_multiple_customers
        if customer_details:
            for customer in customer_details:
                customer_choices.append([customer.id, customer.name])
        if not self.request.session['customer_admin']:
            customer_choices = []
            customer_choices.append([-1, 'All'])
        if self.request.session['customer_admin']:
            branch_choices = []
            branch_choices.append([-1, 'All'])   
        if len(self.request.session['user_queues']) == 0:
            queue_list = list(queue_list)
        else:
            queue_list = self.request.session['user_queues']
        queue_choices = [] 
        have_multiple_queues = False
        if len(queue_list) > 1:
            queue_choices.append([-1, 'All'])
            have_multiple_queues = True
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'True':
            queue_choices = []
            queue_choices.append([-1, 'All'])
        context['have_multiple_queues'] = have_multiple_queues
        for queue in queue_list:
            queue_choices.append([queue.id, queue.name])
        context['form'] = self.form_class(vendor_choices, branch_choices, status_choices, reason_code_choices, customer_choices, queue_choices)
        filter_map = cache.get('status_tracking_report_filter_map_' + str(admin_user.pk))
        if filter_map:
            selected_vendor = filter_map['selected_vendor']
            selected_branch = filter_map['selected_branch']
            selected_customer = filter_map['selected_customer']
            selected_status = filter_map['selected_status']
            selected_reason_code = filter_map['selected_reason_code']
            selected_queue = filter_map['selected_queue']
            start_date = filter_map['start_date']
            end_date = filter_map['end_date']
            daterangeval = filter_map['daterangeval']
        else:
            if len(vendor_details) > 1:
                selected_vendor = '-1'
            else:
                selected_vendor = vendor_details[0].pk
            if len(branch_details) > 1:
                selected_branch = '-1'
            else:
                if self.request.session['customer_admin']:
                    selected_branch = '-1'
                else:    
                    selected_branch = branch_details[0].pk
            if self.request.session['customer_admin']:      
                if len(customer_details) > 1:
                    selected_customer = '-1'
                else:
                    selected_customer = customer_details[0].pk
            else:
                selected_customer = '-1'
            selected_status = '0'
            selected_reason_code = '-1'
            selected_queue = '-1'
            time_offset = pytz.timezone(self.request.session['DEFAULT_TIME_ZONE'])
            start_date = timezone.now() + timedelta(-29)
            to_date = timezone.now()
            from_date = "{:%Y%m%d}".format(start_date)
            to_date = "{:%Y%m%d}".format(to_date)
            fdate = datetime.strptime(from_date,"%Y%m%d").date()
            tdate = datetime.strptime(to_date,"%Y%m%d").date()
            fdatestr = datetime(fdate.year, fdate.month, fdate.day)
            tdatestr = datetime(tdate.year, tdate.month, tdate.day)
            fdtstr = fdatestr.strftime("%Y-%m-%d")
            tdtstr = tdatestr.strftime("%Y-%m-%d")
            daterangeval = fdtstr + str(" - ") + tdtstr
            start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
            end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
            end_date = end_date + relativedelta(days = 1)
            filter_map = {}
            filter_map['selected_vendor'] = selected_vendor
            filter_map['selected_branch'] = selected_branch
            filter_map['selected_status'] = selected_status
            filter_map['selected_customer'] = selected_customer
            filter_map['selected_reason_code'] = selected_reason_code
            filter_map['selected_queue'] = selected_queue
            filter_map['start_date'] = start_date
            filter_map['end_date'] = end_date
            filter_map['daterangeval'] = daterangeval
        cache.set('status_tracking_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        context['form'].fields['vendor'].initial = selected_vendor
        context['form'].fields['branch'].initial = selected_branch
        context['form'].fields['access_customers'].initial = selected_customer
        context['form'].fields['status'].initial = selected_status
        context['form'].fields['reason_code'].initial = selected_reason_code
        context['form'].fields['daterange'].initial = daterangeval
        context['form'].fields['queue'].initial = selected_queue
        status_tracking_report_details = get_status_tracking_report(selected_vendor, selected_branch, selected_status, selected_customer, admin_user.tenant, selected_reason_code, start_date, end_date,  self.request.session['user_vendor_list'], self.request.session['user_branch_list'], self.request.session['user_customers_list'], selected_queue, self.request.session['user_queue_list'])
        context['status_tracking_report_details'] = status_tracking_report_details[0]
        context['is_post'] = True
        context['daterangeval'] = daterangeval
        vendor_list = self.request.session['vendors_with_create_call_list']
        create_ticket = False
        if len(vendor_list) > 0:
            create_ticket = True
        context['create_ticket'] = create_ticket   
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'False':
            self.template_name = 'call_records_list_cipla.html'
        return context
    
    def get(self, request, *args, **kwargs):
        if not can_access_itemname('CALLDETAIL_ITEM', request.session['tenant'], '', request.session['admin_roles'], 1):
            logger.error('Invalid request by User [' + request.user.username + ']: Attempting to access list call details page')
            return HttpResponseRedirect(reverse('request_error'))
        config_map = request.config_map
        if config_map['IS_MULTIPLE_VENDOR_ALLOWED'] == 'False':
            self.template_name = 'call_records_list_cipla.html'
        request.session['active_tab'] = '4'
        return super(ListStatusTrackingReport, self).get(request, args, kwargs)
    
    def get_success_url(self):
        return reverse_lazy(self.redirecturl)
   
    def post(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        time_offset = pytz.timezone(request.session['DEFAULT_TIME_ZONE'])
        selected_vendor = request.POST.get('vendor')
        selected_branch = request.POST.get('branch')
        selected_customer = request.POST.get('access_customers')
        selected_status = request.POST.get('status')
        selected_reason_code = request.POST.get('reason_code')
        selected_queue = request.POST.get('queue')
        daterangeval = request.POST.get('daterange')
        split_set = daterangeval.split(' - ')
        from_date = split_set[0]
        to_date = split_set[1]
        fdate = datetime.strptime(from_date,"%Y-%m-%d").date()
        tdate = datetime.strptime(to_date,"%Y-%m-%d").date()
        start_date = datetime(year = fdate.year, month = fdate.month, day = fdate.day, tzinfo = time_offset)
        end_date = datetime(year = tdate.year, month = tdate.month, day = tdate.day, tzinfo = time_offset)
        end_date = end_date + relativedelta(days = 1)
        filter_map = {}
        filter_map['selected_vendor'] = selected_vendor
        filter_map['selected_branch'] = selected_branch
        filter_map['selected_status'] = selected_status
        filter_map['selected_customer'] = selected_customer
        filter_map['selected_reason_code'] = selected_reason_code
        filter_map['selected_queue'] = selected_queue
        filter_map['start_date'] = start_date
        filter_map['end_date'] = end_date
        filter_map['daterangeval'] = daterangeval
        cache.set('status_tracking_report_filter_map_' + str(admin_user.pk), filter_map, 180)
        return super(ListStatusTrackingReport, self).post(request, args, kwargs)



@class_view_decorator(login_required)
class DisplayStatusTrackingReportDetails(AdminTemplateView):
    template_name = 'display_status_tracking_report.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayStatusTrackingReportDetails, self).get_context_data(**kwargs)
        context['active_tab'] = self.request.session.get('active_tab', '0')
        callobj = CallTicket.objects.get(pk = self.kwargs['pk'])
        context['callobj'] = callobj
        status_reasoncode_map = {}
        status_reasoncode_map[0] = []
        status_list = CallStatus.objects.filter(is_active = True).order_by('rank')
        hide_reason_code_id_list =  []
        hide_reason_code_list = HideCallReasonCodeForVendor.objects.filter(vendor = callobj.vendor, tenant = callobj.tenant, app_type = 1)
        for obj in hide_reason_code_list:
            hide_reason_code_id_list.append(obj.reasoncode.pk)
        for statusobj in status_list:
            status_reasoncode_list = ReasonCode.objects.filter(call_status = statusobj, is_active = True).exclude(id__in = hide_reason_code_id_list).order_by('rank')
            status_reasoncode_map[statusobj.id] = list(status_reasoncode_list)
        context['status_reasoncode_map'] = status_reasoncode_map
        call_machine_list = TicketMachineDetails.objects.filter(ticket = callobj)
        call_line_items_list = TicketLineItem.objects.filter(ticket = callobj).order_by('-line_id')
        call_status_track_list = TicketStatusTrack.objects.filter(ticket = callobj).order_by('-status_change_time')
        call_notes_list = TicketNotes.objects.filter(ticket = callobj).order_by('-notes_entered_time')
        call_document_list = TicketDocument.objects.filter(ticket = callobj).order_by('-upload_time')
        call_customer_feedback_list = TicketCustomerFeedback.objects.filter(ticket = callobj)
        call_engineer_feedback_list = TicketClosureNotes.objects.filter(ticket = callobj)
        call_feedback_list = TicketCallFeedback.objects.filter(ticket = callobj)
        call_changes_audit_list = TicketChangesAudit.objects.filter(ticket = callobj).order_by('-updated_time')
        context['call_machine_list'] = call_machine_list
        context['call_machine_obj']= call_machine_list.first()
        context['call_line_items_list'] = call_line_items_list
        context['call_status_track_list'] = call_status_track_list
        context['call_notes_list'] = call_notes_list
        context['call_document_list'] = call_document_list
        context['call_customer_feedback_list'] = call_customer_feedback_list
        context['call_customer_feedback_obj'] = call_customer_feedback_list.last()
        context['call_engineer_feedback_list'] = call_engineer_feedback_list
        context['call_engineer_feedback_obj'] = call_engineer_feedback_list.last()
        context['call_feedback_obj'] = call_feedback_list.last()
        context['call_changes_audit_list'] = call_changes_audit_list
        call_status_assign_engineer_track_list = AssignedEngineerTrack.objects.filter(ticket = callobj).order_by('-modified_time')
        #context['created_time'] = created_time
        context['call_status_assign_engineer_track_list'] = call_status_assign_engineer_track_list
        reasoncode_fields_map = {}
        reasoncode_list = ReasonCode.objects.filter(call_status__tenant = callobj.tenant, is_active = True).order_by('rank')
        for reasoncode in reasoncode_list:
            field_list = FieldReasonCodeMap.objects.filter(tenant = callobj.tenant, reason_code = reasoncode)
            reasoncode_fields_map[reasoncode.id] = list(field_list)
        context['reasoncode_fields_map'] = reasoncode_fields_map
        reason_code_protected_fields = []
        field_reasoncode_list = FieldReasonCodeMap.objects.filter(tenant = callobj.tenant)
        for field_reasoncode in field_reasoncode_list:
            access_field = field_reasoncode.access_field
            if not access_field.field_id in reason_code_protected_fields:
                reason_code_protected_fields.append(access_field.field_id)
        context['reason_code_protected_fields'] = reason_code_protected_fields
        if callobj.customer:
            severity_level_label = callobj.customer.severity_name
            tier_label = callobj.customer.tier_name
            department_label = callobj.customer.department_name
            location_type_label = callobj.customer.location_type_name
        else:
            tenantvendormappingobj = TenantVendorMapping.objects.filter(tenant = callobj.tenant, vendor = callobj.vendor).first()
            severity_level_label = tenantvendormappingobj.severity_name
            tier_label = tenantvendormappingobj.tier_name
            department_label = tenantvendormappingobj.department_name
            location_type_label = tenantvendormappingobj.location_type_name
        context['severity_level_label'] = severity_level_label    
        context['tier_label'] = tier_label    
        context['department_label'] = department_label 
        context['location_type_label'] = location_type_label
        return context

    def get(self, request, *args, **kwargs):
        admin_user = Administrator.objects.get(pk=request.user.id)
        callobj = CallTicket.objects.get(pk = kwargs['pk'])
        call_machine_list = TicketMachineDetails.objects.filter(ticket = callobj)
        call_line_items_list = TicketLineItem.objects.filter(ticket = callobj).order_by('-line_id')
        call_status_track_list = TicketStatusTrack.objects.filter(ticket = callobj).order_by('-status_change_time')
        call_notes_list = TicketNotes.objects.filter(ticket = callobj).order_by('-notes_entered_time')
        call_document_list = TicketDocument.objects.filter(ticket = callobj).order_by('-upload_time')
        call_customer_feedback_list = TicketCustomerFeedback.objects.filter(ticket = callobj)
        call_engineer_feedback_list = TicketClosureNotes.objects.filter(ticket = callobj)
        call_changes_audit_list = TicketChangesAudit.objects.filter(ticket = callobj).order_by('-updated_time')
        #if admin_user.call_details:
        #    if customer_details.pk != admin_user.customer.id:
        #        return HttpResponseRedirect(reverse('common:common_requesterror'))
        #else:
        #    return HttpResponseRedirect(reverse('common:common_requesterror'))
        self.callobj = callobj
        self.call_machine_list = call_machine_list
        self.call_machine_obj = call_machine_list.first()
        self.call_line_items_list = call_line_items_list
        self.call_status_track_list = call_status_track_list
        self.call_notes_list = call_notes_list
        self.call_document_list = call_document_list
        self.call_changes_audit_list = call_changes_audit_list
        self.call_customer_feedback_list = call_customer_feedback_list
        self.call_customer_feedback_obj = call_customer_feedback_list.first()
        self.call_engineer_feedback_list = call_engineer_feedback_list
        self.call_engineer_feedback_obj = call_engineer_feedback_list.first()
        return super(DisplayStatusTrackingReportDetails, self).get(request, args, kwargs)
    

@class_view_decorator(login_required)
class ListOperatingSystem(AdminListView):
    model = OperatingSystem
    template_name = 'list_operating_system.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = OperatingSystem.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListOperatingSystem, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateOperatingSystem(AdminCreateView):
    model = OperatingSystem
    form_class = CreateOperatingSystemForm
    template_name = 'create_operating_system.html'
    success_message = 'New OperatingSystem created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateOperatingSystem,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateOperatingSystem, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateOperatingSystem,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateOperatingSystem, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New OperatingSystem created successfully'
        return reverse('administrations:list_operating_system')

@class_view_decorator(login_required)
class UpdateOperatingSystemDetails(AdminUpdateView):
    model = OperatingSystem
    form_class = UpdateOperatingSystemDetailsForm
    template_name = 'update_operating_system_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOperatingSystemDetails,self).get_context_data(**kwargs)
        operatingsystemObj = OperatingSystem.objects.get(pk = self.kwargs['pk'])
        context['operatingsystemObj'] = operatingsystemObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateOperatingSystemDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateOperatingSystemDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        operatingsystem_details = OperatingSystem.objects.get(pk = self.kwargs['pk'])
        kw['operatingsystem_details'] = operatingsystem_details
        return kw

    def post(self, request, *args, **kwargs):
        operatingsystemObj = OperatingSystem.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated OperatingSystem details sucessfully!'
        return super(UpdateOperatingSystemDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_operating_system')


@class_view_decorator(login_required)
class ListRAM(AdminListView):
    model = RAM
    template_name = 'list_ram.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = RAM.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListRAM, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateRAM(AdminCreateView):
    model = RAM
    form_class = CreateRAMForm
    template_name = 'create_ram.html'
    success_message = 'New RAM created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateRAM,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        capacity_list = MemoryCapacity.objects.filter(is_active = True, tenant = admin_user.tenant)
        context['form'].fields['capacity'].queryset =  capacity_list
        return context

    def get_form_kwargs(self):
        kw = super(CreateRAM, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateRAM,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateRAM, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New RAM created successfully'
        return reverse('administrations:list_ram')

@class_view_decorator(login_required)
class UpdateRAMDetails(AdminUpdateView):
    model = RAM
    form_class = UpdateRAMDetailsForm
    template_name = 'update_ram_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateRAMDetails,self).get_context_data(**kwargs)
        ramObj = RAM.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        capacity_list = MemoryCapacity.objects.filter(is_active = True, tenant = admin_user.tenant)
        context['form'].fields['capacity'].queryset =  capacity_list
        context['ramObj'] = ramObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateRAMDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateRAMDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        ram_details = RAM.objects.get(pk = self.kwargs['pk'])
        kw['ram_details'] = ram_details
        return kw

    def post(self, request, *args, **kwargs):
        ramObj = RAM.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated RAM details sucessfully!'
        return super(UpdateRAMDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_ram')


@class_view_decorator(login_required)
class ListHardiskType(AdminListView):
    model = HardiskType
    template_name = 'list_hardisktype.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = HardiskType.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListHardiskType, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateHardiskType(AdminCreateView):
    model = HardiskType
    form_class = CreateHardiskTypeForm
    template_name = 'create_hardisktype.html'
    success_message = 'New HardiskType created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateHardiskType,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        capacity_list = MemoryCapacity.objects.filter(is_active = True, tenant = admin_user.tenant)
        context['form'].fields['capacity'].queryset =  capacity_list
        return context

    def get_form_kwargs(self):
        kw = super(CreateHardiskType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateHardiskType,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateHardiskType, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New HardiskType created successfully'
        return reverse('administrations:list_hardisktype')

@class_view_decorator(login_required)
class UpdateHardiskTypeDetails(AdminUpdateView):
    model = HardiskType
    form_class = UpdateHardiskTypeDetailsForm
    template_name = 'update_hardisktype_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateHardiskTypeDetails,self).get_context_data(**kwargs)
        hardisktypeObj = HardiskType.objects.get(pk = self.kwargs['pk'])
        capacity_list = MemoryCapacity.objects.filter(is_active = True, tenant = admin_user.tenant)
        context['form'].fields['capacity'].queryset =  capacity_list
        context['hardisktypeObj'] = hardisktypeObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateHardiskTypeDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateHardiskTypeDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        hardisktype_details = HardiskType.objects.get(pk = self.kwargs['pk'])
        kw['hardisktype_details'] = hardisktype_details
        return kw

    def post(self, request, *args, **kwargs):
        hardisktypeObj = HardiskType.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated HardiskType details sucessfully!'
        return super(UpdateHardiskTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_hardisktype')


@class_view_decorator(login_required)
class ListMemoryCapacity(AdminListView):
    model = MemoryCapacity
    template_name = 'list_memory_capacity.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = MemoryCapacity.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListMemoryCapacity, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class DisplayMemoryCapacityDetails(AdminTemplateView):
    template_name = 'display_memory_capacity_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayMemoryCapacityDetails,self).get_context_data(**kwargs)
        return context

    def get(self, request, *args, **kwargs):
        memory_capacity_details = MemoryCapacity.objects.get(pk = kwargs['pk'])
        self.memory_capacity_details = memory_capacity_details
        return super(DisplayMemoryCapacityDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
class CreateMemoryCapacity(AdminCreateView):
    model = MemoryCapacity
    form_class = CreateMemoryCapacityForm
    template_name = 'create_memory_capacity.html'
    success_message = 'New Capacity created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateMemoryCapacity,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateMemoryCapacity, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateMemoryCapacity,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateMemoryCapacity, self).get(request, args, kwargs)

    def get_success_url(self):
        self.success_message = 'New Capacity created successfully'
        return reverse('administrations:list_memory_capacity')

@class_view_decorator(login_required)
class UpdateMemoryCapacityDetails(AdminUpdateView):
    model = MemoryCapacity
    form_class = UpdateMemoryCapacityDetailForm
    template_name = 'update_memory_capacity_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateMemoryCapacityDetails,self).get_context_data(**kwargs)
        memoryCapacityObj = MemoryCapacity.objects.get(pk = self.kwargs['pk'])
        context['memoryCapacityObj'] = memoryCapacityObj
        return context

    def get(self, request, *args, **kwargs):
        return super(UpdateMemoryCapacityDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateMemoryCapacityDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        memory_capacity_details = MemoryCapacity.objects.get(pk = self.kwargs['pk'])
        kw['memory_capacity_details'] = memory_capacity_details
        return kw

    def post(self, request, *args, **kwargs):
        memoryCapacityObj = MemoryCapacity.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'Updated Capacity details sucessfully!'
        return super(UpdateMemoryCapacityDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_memory_capacity')

# HRMS views
'''@class_view_decorator(login_required)
class ListAdminRoles(AdminListView):
    model = AdminRole
    template_name = 'list_admin_roles.html'

    def get_queryset(self):
        queryset = AdminRole.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateAdminRole(AdminCreateView):
    model = AdminRole
    form_class = AdminRoleForm
    template_name = 'create_admin_role.html'
    success_message = 'New AdminRole created successfully'

    # def get_form_kwargs(self):
    #     kw = super(CreateAdminRole, self).get_form_kwargs()
    #     return kw

    # def form_valid(self, form):
    #     return super(CreateAdminRole,self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('administrations:list_admin_roles')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateAdminRole(AdminUpdateView):
    model = AdminRole
    form_class = AdminRoleForm
    template_name = 'update_admin_role.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateAdminRole,self).get_context_data(**kwargs)
        context['modelobj'] = AdminRole.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateAdminRole, self).get_form_kwargs()
        kw['oldobj'] = AdminRole.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        adminrole = AdminRole.objects.get(pk = kwargs['pk'])
        self.success_message = 'AdminRole \'' + adminrole.name + '\' updated sucessfully!'
        return super(UpdateAdminRole, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_admin_roles')'''


@class_view_decorator(login_required)
class ListOrganizationProject(AdminListView):
    model = OrganizationProject
    template_name = 'list_organization_project.html'
    
    def get_queryset(self):
        queryset = OrganizationProject.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganizationProject(AdminCreateView):
    model = OrganizationProject
    form_class = CreateOrganizationProjectForm
    template_name = 'create_organization_project.html'
    success_message = 'New Project created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateOrganizationProject,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        return context

    def get_form_kwargs(self):
        kw = super(CreateOrganizationProject, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '2'
        return super(CreateOrganizationProject, self).get(request, args, kwargs)

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.tenant = organizationObj.tenant
        return super(CreateOrganizationProject,self).form_valid(form)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':organizationObj.pk})


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationProject(AdminUpdateView):
    model = OrganizationProject
    form_class = UpdateOrganizationProjectForm
    template_name = 'update_organization_project.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationProject,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        context['projectObj'] = OrganizationProject.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationProject, self).get_form_kwargs()
        kw['oldobj'] = OrganizationProject.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '2'
        return super(UpdateOrganizationProject, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        project = OrganizationProject.objects.get(pk = kwargs['pk'])
        self.success_message = 'Project \'' + project.name + '\' updated sucessfully!'
        return super(UpdateOrganizationProject, self).post(request, args, kwargs)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':organizationObj.pk})


'''@class_view_decorator(login_required)
class ListRegion(AdminListView):
    model = Region
    template_name = 'list_region.html'

    def get_queryset(self):
        queryset = Region.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateRegion(AdminCreateView):
    model = Region
    form_class = RegionForm
    template_name = 'create_region.html'
    success_message = 'New Region created successfully'

    # def get_form_kwargs(self):
    #     kw = super(CreateRegion, self).get_form_kwargs()
    #     return kw

    # def form_valid(self, form):
    #     return super(CreateRegion,self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('administrations:list_region')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateRegion(AdminUpdateView):
    model = Region
    form_class = RegionForm
    template_name = 'update_region.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateRegion,self).get_context_data(**kwargs)
        context['modelobj'] = Region.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateRegion, self).get_form_kwargs()
        kw['oldobj'] = Region.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        region = Region.objects.get(pk = kwargs['pk'])
        self.success_message = 'Region \'' + region.name + '\' updated sucessfully!'
        return super(UpdateRegion, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_region')'''


@class_view_decorator(login_required)
class ListGrade(AdminListView):
    model = Grade
    template_name = 'list_grade.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        queryset = Grade.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListGrade, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateGrade(AdminCreateView):
    model = Grade
    form_class = GradeForm
    template_name = 'create_grade.html'
    success_message = 'New Grade created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateGrade,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateGrade, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant        
        return kw

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.tenant = organizationObj.tenant
        return super(CreateGrade,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '3'
        return super(CreateGrade, self).get(request, args, kwargs)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':organizationObj.pk})


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateGrade(AdminUpdateView):
    model = Grade
    form_class = GradeForm
    template_name = 'update_grade.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateGrade,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        context['gradeObj'] = Grade.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateGrade, self).get_form_kwargs()
        kw['oldobj'] = Grade.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def post(self, request, *args, **kwargs):
        gradeObj = Grade.objects.get(pk = kwargs['pk'])
        self.success_message = 'Grade \'' + gradeObj.name + '\' updated sucessfully!'
        return super(UpdateGrade, self).post(request, args, kwargs)
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '3'
        return super(UpdateGrade, self).get(request, args, kwargs)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':organizationObj.pk})


@class_view_decorator(login_required)
class ListOrganizationDepartment(AdminListView):
    model = Department
    template_name = 'list_organization_department.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        queryset = Department.objects.filter(tenant = admin_user.tenant)
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganizationDepartment(AdminCreateView):
    model = OrganizationDepartment
    form_class = OrganizationDepartmentForm
    template_name = 'create_organization_department.html'
    success_message = 'New Department created successfully'

    def get_context_data(self, **kwargs):
        context = super(CreateOrganizationDepartment,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateOrganizationDepartment, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw
    
    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.tenant = organizationObj.tenant
        return super(CreateOrganizationDepartment,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '4'
        return super(CreateOrganizationDepartment, self).get(request, args, kwargs)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':organizationObj.pk})


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationDepartment(AdminUpdateView):
    model = OrganizationDepartment
    form_class = OrganizationDepartmentForm
    template_name = 'update_organization_department.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationDepartment,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        context['departmentobj'] = OrganizationDepartment.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationDepartment, self).get_form_kwargs()
        kw['oldobj'] = OrganizationDepartment.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '4'
        return super(UpdateOrganizationDepartment, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        department = OrganizationDepartment.objects.get(pk = kwargs['pk'])
        self.success_message = 'Department \'' + department.name + '\' updated sucessfully!'
        return super(UpdateOrganizationDepartment, self).post(request, args, kwargs)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':organizationObj.pk})


@class_view_decorator(login_required)
class ListWorkLocation(AdminListView):
    model = WorkLocation
    template_name = 'list_worklocation.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = WorkLocation.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListWorkLocation, self).get(request, args, kwargs)

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateWorkLocation(AdminCreateView):
    model = WorkLocation
    form_class = WorkLocationForm
    template_name = 'create_worklocation.html'
    success_message = 'New WorkLocation created successfully'

    def get_form_kwargs(self):
        kw = super(CreateWorkLocation, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateWorkLocation,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateWorkLocation, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_worklocation')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateWorkLocation(AdminUpdateView):
    model = WorkLocation
    form_class = WorkLocationForm
    template_name = 'update_worklocation.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateWorkLocation,self).get_context_data(**kwargs)
        context['modelobj'] = WorkLocation.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateWorkLocation, self).get_form_kwargs()
        kw['oldobj'] = WorkLocation.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw
    
    def get(self, request, *args, **kwargs):
        return super(UpdateWorkLocation, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        worklocationObj = WorkLocation.objects.get(pk = kwargs['pk'])
        self.success_message = 'WorkLocation \'' + worklocationObj.location_name + '\' updated sucessfully!'
        return super(UpdateWorkLocation, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_worklocation')
    

'''@class_view_decorator(login_required)
class ListDateFormat(AdminListView):
    model = DateFormat
    template_name = 'list_date_format.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = DateFormat.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListDateFormat, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateDateFormat(AdminCreateView):
    model = DateFormat
    form_class = DateFormatForm
    template_name = 'create_date_format.html'
    success_message = 'New DateFormat created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateDateFormat,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateDateFormat, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateDateFormat,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateDateFormat, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_date_format')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateDateFormatDetails(AdminUpdateView):
    model = DateFormat
    form_class = DateFormatForm
    template_name = 'update_date_format_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateDateFormatDetails,self).get_context_data(**kwargs)
        context['modelobj'] = DateFormat.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateDateFormatDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['oldobj'] = DateFormat.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
        
    def post(self, request, *args, **kwargs):
        dateformat = DateFormat.objects.get(pk = kwargs['pk'])
        self.success_message = 'DateFormat \'' + dateformat.format_display + '\' updated sucessfully!'
        return super(UpdateDateFormatDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_date_format')'''


@class_view_decorator(login_required)
class ListOrganization(AdminListView):
    model = Organization
    template_name = 'list_organization.html'

    def get_context_data(self, **kwargs):
        context = super(ListOrganization,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        if organizationObj:
            context['hide_create_organization'] = True
        #context['hide_sidebar'] = True
        return context
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '0'
        return super(ListOrganization, self).get(request, args, kwargs)

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Organization.objects.filter(tenant = admin_user.tenant)
        return queryset
    

def handle_uploaded_file(save_file, f):
    with open(save_file, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganization(AdminCreateView):
    model = Organization
    form_class = CreateOrganizationForm
    template_name = 'create_organization.html'
    success_message = 'New Organization created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateOrganization,self).get_context_data(**kwargs)
        countryObj = Country.objects.filter(name = 'India').first()
        context['form'].fields['business_location'].initial = countryObj
        return context

    def post(self, request, *args, **kwargs):
        self.email = request.POST.get('email', '')
        return super(CreateOrganization, self).post(request, args, kwargs)

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        imagefile = self.request.FILES.get('file', None)
        extension = find_file_extension(imagefile.name)
        name = find_filename_without_extension(imagefile.name)
        filename = remove_spl_char(name) + '_' + str(uuid.uuid4()) + '.' + extension
        handle_uploaded_file(settings.UPLOADS_DIR + '/' + filename, imagefile)
        form.instance.logo_url = '/file/' + filename
        return super(CreateOrganization, self).form_valid(form)
    
    def get_form_kwargs(self):
        kw = super(CreateOrganization, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['organizationObj']  = Organization.objects.filter(tenant = admin_user.tenant).first()
        return kw

    def get(self, request, *args, **kwargs):
        return super(CreateOrganization, self).get(request, args, kwargs)

    def get_success_url(self):
        organizationObj = Organization.objects.get(pk = self.object.pk)
        organization_contact = OrganizationContact(organization = organizationObj, email = self.email, name =  'Primary', is_primary = True)
        organization_contact.save()
        #return reverse_lazy('administrations:list_organization')
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':self.object.pk})


@class_view_decorator(login_required)
class DisplayOrganizationDetails(AdminTemplateView):
    template_name = 'display_organization_details.html'

    def get_context_data(self, **kwargs):
        context = super(DisplayOrganizationDetails,self).get_context_data(**kwargs)
        context['active_tab'] = self.request.session.get('active_tab', '0')
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(pk = self.kwargs['pk'], tenant = admin_user.tenant).first()
        organization_contact_list = OrganizationContact.objects.filter(organization = organizationObj)
        context['organization_contact_list'] = organization_contact_list
        organization_project_list = OrganizationProject.objects.filter(tenant = organizationObj.tenant)
        context['organization_project_list'] = organization_project_list
        grade_list = Grade.objects.filter(tenant = organizationObj.tenant)
        context['grade_list'] = grade_list
        organization_department_list = OrganizationDepartment.objects.filter(tenant = organizationObj.tenant)
        context['organization_department_list'] = organization_department_list
        context['organizationObj'] = organizationObj
        return context

    def get(self, request, *args, **kwargs):
        return super(DisplayOrganizationDetails, self).get(request, args, kwargs)

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationDetails(AdminUpdateView):
    model = Organization
    form_class = UpdateOrganizationDetailForm
    template_name = 'update_organization_details.html'
    success_message = 'Organization Updated successfully'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(pk = self.kwargs['pk'], tenant = admin_user.tenant).first()
        organization_contact_list = OrganizationContact.objects.filter(organization = organizationObj)
        context['organization_contact_list'] = organization_contact_list
        context['organizationObj'] = organizationObj
        return context

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['oldobj'] = Organization.objects.filter(pk = self.kwargs['pk'], tenant = admin_user.tenant).first()
        kw['is_update'] = True
        return kw

    def get(self, request, *args, **kwargs):
        return super(UpdateOrganizationDetails, self).get(request, args, kwargs)

    def form_valid(self, form):
        imagefile = self.request.FILES.get('file', None)
        if imagefile:
            extension = find_file_extension(imagefile.name)
            name = find_filename_without_extension(imagefile.name)
            filename = remove_spl_char(name) + '_' + str(uuid.uuid4()) + '.' + extension
            handle_uploaded_file(settings.UPLOADS_DIR + '/' + filename, imagefile)
            form.instance.logo_url = '/file/' + filename
        return super(UpdateOrganizationDetails,self).form_valid(form)

    def post(self, request, *args, **kwargs):
        request.session['active_tab'] = '0'
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organization = Organization.objects.filter(pk = kwargs['pk'], tenant = admin_user.tenant).first()
        self.success_message = 'Organization \'' + organization.name + '\' updated sucessfully!'
        self.email = request.POST.get('email', '')
        return super(UpdateOrganizationDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        organizationObj = Organization.objects.filter(pk = self.kwargs['pk'])
        #return reverse_lazy('administrations:list_organization', kwargs={'pk':self.kwargs['organizationObj']})
        #return reverse('administrations:display_organization_details', kwargs={'pk':self.object.pk})
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':self.kwargs['pk']})


@class_view_decorator(login_required)
class ListOrganizationContact(AdminListView):
    model = OrganizationContact
    template_name = 'list_organization_contact.html'
        
    def get_context_data(self, **kwargs):
        context = super(ListOrganizationContact,self).get_context_data(**kwargs)
        context['organization_id'] = self.kwargs['pk']
        #organizationObj = Organization.objects.get(pk = self.kwargs['pk'])
        context['hide_sidebar'] = True
        context['hide_primary_field'] = True
        return context
    
    def get_queryset(self):
        queryset = OrganizationContact.objects.filter(organization = self.kwargs['pk'])
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganizationContact(AdminCreateView):
    model = OrganizationContact
    form_class = CreateOrganizationContactForm
    template_name = 'create_organization_contact.html'
    success_message = 'New Organization Contact created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateOrganizationContact,self).get_context_data(**kwargs)
        organizationObj =  Organization.objects.get(pk = self.kwargs['organization_id'])
        context['organizationObj'] = organizationObj
        if OrganizationContact.objects.filter(organization = organizationObj, is_primary = True).exists():
            context['form'].fields['is_primary'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'Is Primary already exist with Organization, so you won\'t be able to uncheck the Is Primary'}
        return context
    
    def form_valid(self, form):
        organizationObj = Organization.objects.get(pk = self.kwargs['organization_id'])
        form.instance.organization = organizationObj
        return super(CreateOrganizationContact,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '1'
        return super(CreateOrganizationContact, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        #self.success_message = 'Call Notes created sucessfully!'
        return super(CreateOrganizationContact, self).post(request, args, kwargs)
    
    def get_success_url(self):
        #organizationObj = Organization.objects.get(pk = self.kwargs['pk'])
        #return reverse('administrations:update_organization_details', kwargs={'pk':self.kwargs['organization_id']})
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':self.kwargs['organization_id']})


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationContactDetails(AdminUpdateView):
    model = OrganizationContact
    form_class = UpdateOrganizationContactDetailForm
    template_name = 'update_organization_contact_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationContactDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(pk = self.kwargs['organization_id'], tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        organizationContactObj  = OrganizationContact.objects.get(pk = self.kwargs['pk'])
        context['organizationContactObj'] = organizationContactObj
        context['organization_id'] = self.kwargs['organization_id']
        if OrganizationContact.objects.filter(organization = organizationContactObj.organization, is_primary = True).exists():
            context['form'].fields['is_primary'].widget.attrs = {'onclick': 'return false;', 'class': 'custom-control-input', 'data-container': 'body', 'data-toggle':'popover', 'data-placement':'right', 'data-content':'Is Primary already exist with Organization, so you won\'t be able to uncheck the Is Primary'}
        return context
    
    def get(self, request, *args, **kwargs):
        request.session['active_tab'] = '1'
        return super(UpdateOrganizationContactDetails, self).get(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationContactDetails, self).get_form_kwargs()
        kw['oldobj'] = OrganizationContact.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def post(self, request, *args, **kwargs):
        organizationcontact = OrganizationContact.objects.get(pk = kwargs['pk'])
        self.success_message = 'Organization Contact \'' + organizationcontact.name + '\' updated sucessfully!'
        return super(UpdateOrganizationContactDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:display_organization_details', kwargs={'pk':self.kwargs['organization_id']})
        


@class_view_decorator(login_required)
class ListStatutoryComponents(AdminListView):
    model = OrganizationESIDetails
    template_name = 'list_statutory_components.html'
    
    def get_context_data(self, **kwargs):
        context = super(ListStatutoryComponents,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        organization_epf_details_list = OrganizationEmployeePFDetails.objects.filter(organization = organizationObj)
        context['organization_epf_details_list'] = organization_epf_details_list
        #organization_project_list = OrganizationProject.objects.filter(tenant = organizationObj.tenant)
        #context['organization_project_list'] = organization_project_list
        #grade_list = Grade.objects.filter(tenant = organizationObj.tenant)
        #context['grade_list'] = grade_list
        #organization_department_list = OrganizationDepartment.objects.filter(tenant = organizationObj.tenant)
        #context['organization_department_list'] = organization_department_list
        context['organizationObj'] = organizationObj
        return context

    def get_queryset(self):
        #organizationObj = Organization.objects.filter(pk = self.kwargs['pk'], tenant = admin_user.tenant).first()
        queryset = OrganizationESIDetails.objects.all()
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListStatutoryComponents, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganizationESIDetails(AdminCreateView):
    model = OrganizationESIDetails
    form_class = OrganizationESIDetailsForm
    template_name = 'create_organization_esi_details.html'
    success_message = 'New Organization ESI Details created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateOrganizationESIDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateOrganizationESIDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['organization'] = Organization.objects.filter(tenant = admin_user.tenant).first()
        return kw

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.organization = organizationObj
        return super(CreateOrganizationESIDetails,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateOrganizationESIDetails, self).get(request, args, kwargs)

    def get_success_url(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        return reverse_lazy('administrations:list_statutory_components')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationESIDetails(AdminUpdateView):
    model = OrganizationESIDetails
    form_class = OrganizationESIDetailsForm
    template_name = 'update_organization_esi_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationESIDetails,self).get_context_data(**kwargs)
        context['organizationEsiObj'] = OrganizationESIDetails.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationESIDetails, self).get_form_kwargs()
        kw['oldobj'] = OrganizationESIDetails.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def post(self, request, *args, **kwargs):
        organizationesidetails = OrganizationESIDetails.objects.get(pk = kwargs['pk'])
        self.success_message = 'Organization ESI Details \'' + organizationesidetails.esi_number + '\' updated sucessfully!'
        return super(UpdateOrganizationESIDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_statutory_components')


@class_view_decorator(login_required)
class ListOrganizationEmployeePFDetails(AdminListView):
    model = OrganizationEmployeePFDetails
    template_name = 'list_organization_employee_pf_details.html'

    def get_queryset(self):
        queryset = OrganizationEmployeePFDetails.objects.all()
        return queryset
        
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganizationEmployeePFDetails(AdminCreateView):
    model = OrganizationEmployeePFDetails
    form_class = OrganizationEmployeePFDetailsForm
    template_name = 'create_organization_employee_pf_details.html'
    success_message = 'New Organization Employee PF Details created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateOrganizationEmployeePFDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        return context
    
    def get_form_kwargs(self):
        kw = super(CreateOrganizationEmployeePFDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['organization'] = Organization.objects.filter(tenant = admin_user.tenant).first()
        return kw

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.organization = organizationObj
        return super(CreateOrganizationEmployeePFDetails,self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('administrations:list_statutory_components')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationEmployeePFDetails(AdminUpdateView):
    model = OrganizationEmployeePFDetails   
    form_class = OrganizationEmployeePFDetailsForm
    template_name = 'update_organization_employee_pf_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationEmployeePFDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        context['organizationEmployeePFObj'] = OrganizationEmployeePFDetails.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationEmployeePFDetails, self).get_form_kwargs()
        kw['oldobj'] = OrganizationEmployeePFDetails.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def post(self, request, *args, **kwargs):
        organization_employeepf_details = OrganizationEmployeePFDetails.objects.get(pk = kwargs['pk'])
        self.success_message = 'Organization Employee PF Details \'' + organization_employeepf_details.epf_number + '\' updated sucessfully!'
        return super(UpdateOrganizationEmployeePFDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_statutory_components')


@class_view_decorator(login_required)
class ListOrganizationTaxDetails(AdminListView):
    model = OrganizationTaxDetails
    template_name = 'list_organization_tax_details.html'

    def get_queryset(self):
        queryset = OrganizationTaxDetails.objects.all()
        return queryset
        
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateOrganizationTaxDetails(AdminCreateView):
    model = OrganizationTaxDetails
    form_class = OrganizationTaxDetailsForm
    template_name = 'create_organization_tax_details.html'
    success_message = 'New Organization Tax Details created successfully'

    def get_success_url(self):
        return reverse_lazy('administrations:list_organization_tax_details')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateOrganizationTaxDetails(AdminUpdateView):
    model = OrganizationTaxDetails
    form_class = OrganizationTaxDetailsForm
    template_name = 'update_organization_tax_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateOrganizationTaxDetails,self).get_context_data(**kwargs)
        context['modelobj'] = OrganizationTaxDetails.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateOrganizationTaxDetails, self).get_form_kwargs()
        kw['oldobj'] = OrganizationTaxDetails.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def post(self, request, *args, **kwargs):
        organization_tax_details = OrganizationTaxDetails.objects.get(pk = kwargs['pk'])
        self.success_message = 'Organization Tax Details \'' + organization_tax_details.pan + '\' updated sucessfully!'
        return super(UpdateOrganizationTaxDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_organization_tax_details')


@class_view_decorator(login_required)
class ListProfessionalTaxLocation(AdminListView):
    model = ProfessionalTaxLocation
    template_name = 'list_professional_tax_location.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        queryset = ProfessionalTaxLocation.objects.filter(organization = organizationObj)
        return queryset
        
@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateProfessionalTaxLocation(AdminCreateView):
    model = ProfessionalTaxLocation
    form_class = ProfessionalTaxLocationForm
    template_name = 'create_professional_tax_location.html'
    success_message = 'New Organization Tax Details created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateProfessionalTaxLocation,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        return context

    def get_form_kwargs(self):
        kw = super(CreateProfessionalTaxLocation, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        kw['organization'] = organizationObj     
        return kw

    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.organization = organizationObj
        return super(CreateProfessionalTaxLocation,self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('administrations:list_statutory_components')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateProfessionalTaxLocationDetails(AdminUpdateView):
    model = ProfessionalTaxLocation
    form_class = ProfessionalTaxLocationForm
    template_name = 'update_professional_tax_location_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateProfessionalTaxLocationDetails,self).get_context_data(**kwargs)
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        context['organizationObj'] = organizationObj
        context['taxLocationObj'] = ProfessionalTaxLocation.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateProfessionalTaxLocationDetails, self).get_form_kwargs()
        kw['oldobj'] = ProfessionalTaxLocation.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def post(self, request, *args, **kwargs):
        professional_tax_location_details = ProfessionalTaxLocation.objects.get(pk = kwargs['pk'])
        self.success_message = 'Organization Tax Details \'' + professional_tax_location_details.pt_number + '\' updated sucessfully!'
        return super(UpdateProfessionalTaxLocationDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_statutory_components')


@class_view_decorator(login_required)
class ListEmployeeBenefit(AdminListView):
    model = EmployeeBenefit
    template_name = 'list_employee_benefit.html'

    def get_queryset(self):
        queryset = EmployeeBenefit.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEmployeeBenefit(AdminCreateView):
    model = EmployeeBenefit
    form_class = EmployeeBenefitForm
    template_name = 'create_employee_benefit.html'
    success_message = 'New EmployeeBenefit created successfully'
    
    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_benefit')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeeBenefit(AdminUpdateView):
    model = EmployeeBenefit
    form_class = EmployeeBenefitForm
    template_name = 'update_employee_benefit.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeeBenefit,self).get_context_data(**kwargs)
        context['modelobj'] = EmployeeBenefit.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeeBenefit, self).get_form_kwargs()
        kw['oldobj'] = EmployeeBenefit.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        employeebenefit = EmployeeBenefit.objects.get(pk = kwargs['pk'])
        self.success_message = 'EmployeeBenefit \'' + employeebenefit.name + '\' updated sucessfully!'
        return super(UpdateEmployeeBenefit, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_benefit')


@class_view_decorator(login_required)
class ListProfessionalTaxSlabs(AdminListView):
    model = ProfessionalTaxSlabs
    template_name = 'list_professional_taxslabs.html'

    def get_queryset(self):
        queryset = ProfessionalTaxSlabs.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateProfessionalTaxSlabs(AdminCreateView):
    model = ProfessionalTaxSlabs
    form_class = ProfessionalTaxSlabsForm
    template_name = 'create_professional_taxslabs.html'
    success_message = 'New ProfessionalTaxSlabs created successfully'
    
    def get_success_url(self):
        return reverse_lazy('administrations:list_professional_taxslabs')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateProfessionalTaxSlabs(AdminUpdateView):
    model = ProfessionalTaxSlabs
    form_class = ProfessionalTaxSlabsForm
    template_name = 'update_professional_taxslabs.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateProfessionalTaxSlabs,self).get_context_data(**kwargs)
        context['modelobj'] = ProfessionalTaxSlabs.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateProfessionalTaxSlabs, self).get_form_kwargs()
        kw['oldobj'] = ProfessionalTaxSlabs.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        professionaltaxslabs = ProfessionalTaxSlabs.objects.get(pk = kwargs['pk'])
        self.success_message = 'ProfessionalTaxSlabs \'' + professionaltaxslabs.professional_tax_location + '\' updated sucessfully!'
        return super(UpdateProfessionalTaxSlabs, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_professional_taxslabs')


@class_view_decorator(login_required)
class ListPaySchedule(AdminListView):
    model = PaySchedule
    template_name = 'list_Pay_schedule.html'

    def get_queryset(self):
        queryset = PaySchedule.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreatePaySchedule(AdminCreateView):
    model = PaySchedule
    form_class = PayScheduleForm
    template_name = 'create_Pay_schedule.html'
    success_message = 'New PaySchedule created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreatePaySchedule,self).get_context_data(**kwargs)
        
        context['form'].fields['pay_day'].initial = 1
        context['form'].fields['salary_days_in_month'].initial = 30
        pay_your_empolyee_on_choices = []
        pay_your_empolyee_on_choices.append([0, '----------'])
        pay_your_empolyee_on_choices.append([1, 'Day of every month'])
        pay_your_empolyee_on_choices.append([2, 'The last day of every month'])
        context['form'].fields['pay_your_empolyee_on'].choices =  pay_your_empolyee_on_choices
        context['modelobj']  = PaySchedule.objects.all()
        time_offset = pytz.timezone(self.request.session['DEFAULT_TIME_ZONE'])
        #yearVal = '2020';
        #monthVal = '05';
        #temp_val = get_first_last_day_of_month(yearVal, monthVal, time_offset)
        #lastday_val = get_first_last_day_of_month('2020', '05', time_offset)
        #context['form'].fields['select_a_pay_date'].initial = lastday_val['end_date']
        return context
    
    def post(self, request, *args, **kwargs):
        self.pay_your_empolyee_on = request.POST.get('pay_your_empolyee_on', '')
        self.select_a_pay_date = request.POST.get('select_a_pay_date', '')
        console.log("select_a_pay_date", select_a_pay_date)
        return super(CreatePaySchedule, self).post(request, args, kwargs)

    def get_form_kwargs(self):
        kw = super(CreatePaySchedule, self).get_form_kwargs()
        return kw

    def post(self, request, *args, **kwargs):
        return super(CreatePaySchedule, self).post(request, args, kwargs)

    def get_success_url(self):
        pay_your_empolyee = PaySchedule(pay_your_empolyee_on = self.pay_your_empolyee_on, select_a_pay_date = self.select_a_pay_date)
        pay_your_empolyee.save()
        return reverse_lazy('administrations:list_Pay_schedule')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdatePayScheduleDetails(AdminUpdateView):
    model = PaySchedule
    form_class = PayScheduleForm
    template_name = 'update_Pay_schedule_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdatePayScheduleDetails,self).get_context_data(**kwargs)
        context['form'].fields['pay_day'].initial = 1
        context['form'].fields['salary_days_in_month'].initial = 30
        pay_your_empolyee_on_choices = []
        pay_your_empolyee_on_choices.append([1, 'Day of every month'])
        pay_your_empolyee_on_choices.append([2, 'The last day of every month'])
        context['form'].fields['pay_your_empolyee_on'].choices =  pay_your_empolyee_on_choices
        context['modelobj'] = PaySchedule.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdatePayScheduleDetails, self).get_form_kwargs()
        kw['oldobj'] = PaySchedule.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        payschedule = PaySchedule.objects.get(pk = kwargs['pk'])
        self.success_message = 'PaySchedule \'' + payschedule.first_pay_period + '\' updated sucessfully!'
        return super(UpdatePayScheduleDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_Pay_schedule')


@class_view_decorator(login_required)
class ListPreferences(AdminListView):
    model = Preferences
    template_name = 'list_preferences.html'

    def get_queryset(self):
        queryset = Preferences.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreatePreferences(AdminCreateView):
    model = Preferences
    form_class = PreferencesForm
    template_name = 'create_preferences.html'
    success_message = 'New Preferences created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreatePreferences,self).get_context_data(**kwargs)
        context['modelobj']  = Preferences.objects.all()
        return context
    
    def get_success_url(self):
        return reverse_lazy('administrations:list_preferences')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdatePreferencesDetails(AdminUpdateView):
    model = Preferences
    form_class = PreferencesForm
    template_name = 'update_preferences_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdatePreferencesDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Preferences.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdatePreferencesDetails, self).get_form_kwargs()
        kw['oldobj'] = Preferences.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        preferences = Preferences.objects.get(pk = kwargs['pk'])
        self.success_message = 'Preferences Type updated sucessfully!'
        return super(UpdatePreferencesDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_preferences')


@class_view_decorator(login_required)
class ListCountry(AdminListView):
    model = Country
    template_name = 'list_country.html'

    def get_queryset(self):
        queryset = Country.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateCountry(AdminCreateView):
    model = Country
    form_class = CountryForm
    template_name = 'create_country.html'
    success_message = 'New Country created successfully'
    
    def get_success_url(self):
        return reverse_lazy('administrations:list_country')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateCountryDetails(AdminUpdateView):
    model = Country
    form_class = CountryForm
    template_name = 'update_country_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateCountryDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Country.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateCountryDetails, self).get_form_kwargs()
        kw['oldobj'] = Country.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        country = Country.objects.get(pk = kwargs['pk'])
        self.success_message = 'Country \'' + country.name + '\' updated sucessfully!'
        return super(UpdateCountryDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_country')

@class_view_decorator(login_required)
class ListState(AdminListView):
    model = State
    template_name = 'list_state.html'

    def get_queryset(self):
        queryset = State.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateState(AdminCreateView):
    model = State
    form_class = StateForm
    template_name = 'create_state.html'
    success_message = 'New State created successfully'
    
    def get_success_url(self):
        return reverse_lazy('administrations:list_state')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateStateDetails(AdminUpdateView):
    model = State
    form_class = StateForm
    template_name = 'update_state_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateStateDetails,self).get_context_data(**kwargs)
        context['modelobj'] = State.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateStateDetails, self).get_form_kwargs()
        kw['oldobj'] = State.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        state = State.objects.get(pk = kwargs['pk'])
        self.success_message = 'State \'' + state.name + '\' updated sucessfully!'
        return super(UpdateStateDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_state')


@class_view_decorator(login_required)
class ListSalaryComponents(AdminListView):
    model = Earning
    template_name = 'list_salary_components.html'

    def get_context_data(self, **kwargs):
        context = super(ListSalaryComponents,self).get_context_data(**kwargs)
        deduction_list = Deduction.objects.all()
        context['deduction_list'] = deduction_list
        return context

    def get_queryset(self):
        queryset = Earning.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEarning(AdminCreateView):
    model = Earning
    form_class = CreateEarningForm
    template_name = 'create_earning.html'
    success_message = 'New Earning created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateEarning,self).get_context_data(**kwargs)
        earning_type_map = {}
        earning_type_list = EarningType.objects.all()
        component_configItem_list = ComponentConfigItem.objects.all()
        if earning_type_list:
            for earning_type in earning_type_list:
                earningTypeConfig = EarningTypeComponentConfigItemMapping.objects.filter(earning_type = earning_type)
                earning_type_map[earning_type.id] = earningTypeConfig
        context['earning_type_map'] =  earning_type_map

        return context
    
    def post(self, request, *args, **kwargs):
        return super(CreateEarning, self).post(request, args, kwargs)

    def get_success_url(self):
        earning_type_id = self.request.POST.get('earning_type')
        earningTypeObj = EarningType.objects.get(pk = earning_type_id)
        earningObj = Earning.objects.get(pk = self.object.pk)
        configItemList = ComponentConfigItem.objects.all()
        valueMap = {}
        for configItem in configItemList:
            configItemName = (configItem.config_name).replace(" ", "_").lower()
            defaultVal = self.request.POST.get(configItemName, False)
            if defaultVal == 'on':
                defaultVal = True
            valueMap[configItem.pk] = defaultVal
        for key, value in valueMap.items():
            configItemObj = ComponentConfigItem.objects.get(pk = key)
            #earningTypeConfigItemObj = EarningTypeComponentConfigItemMapping.objects.filter(earning_type = earningTypeObj, configuration = configItemObj).first()
            earningConfigItemObj = EarningComponentConfigItemMapping(earning = earningObj, configuration = configItemObj, value = value)
            earningConfigItemObj.save()
        return reverse_lazy('administrations:list_salary_components')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEarningDetails(AdminUpdateView):
    model = Earning
    form_class = UpdateEarningDetailForm
    template_name = 'update_earning_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEarningDetails,self).get_context_data(**kwargs)
        earningObj = Earning.objects.get(pk = self.kwargs['pk'])
        earning_map = {}
        earning_type_config_map = {}
        earningConfigObj = EarningComponentConfigItemMapping.objects.filter(earning = earningObj)
        earning_map[earningObj.id] = earningConfigObj
        earningTypeObj = EarningType.objects.get(pk = earningObj.earning_type.id)
        earning_type_config_list = EarningTypeComponentConfigItemMapping.objects.filter(earning_type = earningTypeObj)
        for earning_type_config in earning_type_config_list:
            earning_type_config_map[earning_type_config.configuration.id] = earning_type_config
        context['earning_type_config_map'] = earning_type_config_map
        context['earning_map'] =  earning_map
        context['modelobj'] = earningObj
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEarningDetails, self).get_form_kwargs()
        kw['oldobj'] = Earning.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        earning = Earning.objects.get(pk = kwargs['pk'])
        self.success_message = 'Earning \'' + earning.earning_name + '\' updated sucessfully!'
        return super(UpdateEarningDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        earning_type_id = self.request.POST.get('earning_type')
        earningObj = Earning.objects.get(pk = self.kwargs['pk'])        
        earningConfigItemObj = EarningComponentConfigItemMapping.objects.filter(earning = earningObj)
        for earningConfigItem in earningConfigItemObj:
            configItemObj = ComponentConfigItem.objects.get(pk = earningConfigItem.configuration.pk)
            configItemName = (configItemObj.config_name).replace(" ", "_").lower()
            defaultVal = self.request.POST.get(configItemName, False)
            if defaultVal == 'on':
                defaultVal = True
            earningConfigItem.value = defaultVal
            earningConfigItem.save()
        return reverse_lazy('administrations:list_salary_components')


@class_view_decorator(login_required)
class ListDeduction(AdminListView):
    model = Deduction
    template_name = 'list_deduction.html'

    def get_queryset(self):
        queryset = Deduction.objects.all()
        return queryset

    def get(self, request, *args, **kwargs): 
        request.session['active_tab'] = '2'
        return super(ListDeduction, self).get(request, args, kwargs)

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateDeduction(AdminCreateView):
    model = Deduction
    form_class = CreateDeductionForm
    template_name = 'create_deduction.html'
    success_message = 'New Deduction created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateDeduction,self).get_context_data(**kwargs)
        deduction_group_list = DeductionAssociationGroup.objects.filter(is_active = True)
        deduction_associate_with_list = []
        deduction_associate_with_list.append(['0', '---------'])
        for deduction_group in deduction_group_list:
            deductionAssociationObj = DeductionAssociation.objects.filter(association_group = deduction_group)
            deduction_association_list = []
            for deduction_association in deductionAssociationObj:
                deduction_association_tuple = (deduction_association.id, deduction_association.association_name)
                deduction_association_list.append(deduction_association_tuple)
            deduction_group_tuple = (deduction_group.group_name, deduction_association_list)
            deduction_associate_with_list.append(deduction_group_tuple)
        context['form'].fields['deduction_associate_with'].choices =  deduction_associate_with_list
        return context
    
    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        organizationObj = Organization.objects.filter(tenant = admin_user.tenant).first()
        form.instance.organization = organizationObj
        return super(CreateDeduction,self).form_valid(form)
   
    def get_success_url(self):
        return reverse_lazy('administrations:list_salary_components')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateDeductionDetails(AdminUpdateView):
    model = Deduction
    form_class = UpdateDeductionDetailForm
    template_name = 'update_deduction_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateDeductionDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Deduction.objects.get(pk = self.kwargs['pk'])
        deduction_group_list = DeductionAssociationGroup.objects.filter(is_active = True)
        deduction_associate_with_list = []
        deduction_associate_with_list.append(['0', '---------'])
        for deduction_group in deduction_group_list:
            deductionAssociationObj = DeductionAssociation.objects.filter(association_group = deduction_group)
            deduction_association_list = []
            for deduction_association in deductionAssociationObj:
                deduction_association_tuple = (deduction_association.id, deduction_association.association_name)
                deduction_association_list.append(deduction_association_tuple)
            deduction_group_tuple = (deduction_group.group_name, deduction_association_list)
            deduction_associate_with_list.append(deduction_group_tuple)
        context['form'].fields['deduction_associate_with'].choices =  deduction_associate_with_list
        return context

    def get_form_kwargs(self):
        kw = super(UpdateDeductionDetails, self).get_form_kwargs()
        kw['oldobj'] = Deduction.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        deduction = Deduction.objects.get(pk = kwargs['pk'])
        self.success_message = 'Deduction \'' + deduction.display_name_in_payslip + '\' updated sucessfully!'
        return super(UpdateDeductionDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_salary_components')


@class_view_decorator(login_required)
class ListSourceOfHire(AdminListView):
    model = SourceOfHire
    template_name = 'list_source_of_hire.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = SourceOfHire.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListSourceOfHire, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateSourceOfHire(AdminCreateView):
    model = SourceOfHire
    form_class = SourceOfHireForm
    template_name = 'create_source_of_hire.html'
    success_message = 'New SourceOfHire created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateSourceOfHire,self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kw = super(CreateSourceOfHire, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateSourceOfHire,self).form_valid(form)

    def get(self, request, *args, **kwargs):
        return super(CreateSourceOfHire, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_source_of_hire')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateSourceOfHireDetails(AdminUpdateView):
    model = SourceOfHire
    form_class = SourceOfHireForm
    template_name = 'update_source_of_hire_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSourceOfHireDetails,self).get_context_data(**kwargs)
        context['modelobj'] = SourceOfHire.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateSourceOfHireDetails, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['oldobj'] = SourceOfHire.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw
    
    def get(self, request, *args, **kwargs):
        return super(UpdateSourceOfHireDetails, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        sourceofhire = SourceOfHire.objects.get(pk = kwargs['pk'])
        self.success_message = 'Source Of Hire \'' + sourceofhire.name + '\' updated sucessfully!'
        return super(UpdateSourceOfHireDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_source_of_hire')


@class_view_decorator(login_required)
class ListRelationship(AdminListView):
    model = Relationship
    template_name = 'list_relationship.html'
    
    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Relationship.objects.filter(tenant = admin_user.tenant)
        return queryset

    def get(self, request, *args, **kwargs):
        return super(ListRelationship, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateRelationship(AdminCreateView):
    model = Relationship
    form_class = RelationshipForm
    template_name = 'create_relationship.html'
    success_message = 'New Relationship created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateRelationship, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateRelationship,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateRelationship, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_relationship')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateRelationshipDetails(AdminUpdateView):
    model = Relationship
    form_class = RelationshipForm
    template_name = 'update_relationship_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateRelationshipDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Relationship.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateRelationshipDetails, self).get_form_kwargs()
        kw['oldobj'] = Relationship.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw
    
    def get(self, request, *args, **kwargs):
        return super(UpdateRelationshipDetails, self).get(request, args, kwargs)

    def post(self, request, *args, **kwargs):
        relationship = Relationship.objects.get(pk = kwargs['pk'])
        self.success_message = 'Relationship \'' + relationship.name + '\' updated sucessfully!'
        return super(UpdateRelationshipDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_relationship')


@class_view_decorator(login_required)
class ListRole(AdminListView):
    model = Role
    template_name = 'list_role.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Role.objects.filter(tenant = admin_user.tenant)
        return queryset
    
    def get(self, request, *args, **kwargs):
        return super(ListRole, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateRole(AdminCreateView):
    model = Role
    form_class = RoleForm
    template_name = 'create_role.html'
    success_message = 'New Role created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateRole, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateRole,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateRole, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_role')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateRoleDetails(AdminUpdateView):
    model = Role
    form_class = RoleForm
    template_name = 'update_role_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateRoleDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Role.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateRoleDetails, self).get_form_kwargs()
        kw['oldobj'] = Role.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        role = Role.objects.get(pk = kwargs['pk'])
        self.success_message = 'Role \'' + role.name + '\' updated sucessfully!'
        return super(UpdateRoleDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_role')


@class_view_decorator(login_required)
class ListBloodGroup(AdminListView):
    model = BloodGroup
    template_name = 'list_bloodgroup.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = BloodGroup.objects.filter(tenant = admin_user.tenant)
        return queryset
    
    def get(self, request, *args, **kwargs):
        return super(ListBloodGroup, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateBloodGroup(AdminCreateView):
    model = BloodGroup
    form_class = BloodGroupForm
    template_name = 'create_bloodgroup.html'
    success_message = 'New BloodGroup created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateBloodGroup, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateBloodGroup,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateBloodGroup, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_bloodgroup')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateBloodGroupDetails(AdminUpdateView):
    model = BloodGroup
    form_class = BloodGroupForm
    template_name = 'update_bloodgroup_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateBloodGroupDetails,self).get_context_data(**kwargs)
        context['modelobj'] = BloodGroup.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateBloodGroupDetails, self).get_form_kwargs()
        kw['oldobj'] = BloodGroup.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        bloodgroup = BloodGroup.objects.get(pk = kwargs['pk'])
        self.success_message = 'BloodGroup \'' + bloodgroup.name + '\' updated sucessfully!'
        return super(UpdateBloodGroupDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_bloodgroup')


@class_view_decorator(login_required)
class ListGender(AdminListView):
    model = Gender
    template_name = 'list_gender.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = Gender.objects.filter(tenant = admin_user.tenant)
        return queryset
    
    def get(self, request, *args, **kwargs):
        return super(ListGender, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateGender(AdminCreateView):
    model = Gender
    form_class = GenderForm
    template_name = 'create_gender.html'
    success_message = 'New Gender created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateGender, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateGender,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateGender, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_gender')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateGenderDetails(AdminUpdateView):
    model = Gender
    form_class = GenderForm
    template_name = 'update_gender_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateGenderDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Gender.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateGenderDetails, self).get_form_kwargs()
        kw['oldobj'] = Gender.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        gender = Gender.objects.get(pk = kwargs['pk'])
        self.success_message = 'Gender \'' + gender.name + '\' updated sucessfully!'
        return super(UpdateGenderDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_gender')


@class_view_decorator(login_required)
class ListInvestmentType(AdminListView):
    model = InvestmentType
    template_name = 'list_investment_type.html'
        
    def get_queryset(self):
        queryset = InvestmentType.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateInvestmentType(AdminCreateView):
    model = InvestmentType
    form_class = InvestmentTypeForm
    template_name = 'create_investment_type.html'
    success_message = 'New InvestmentType created successfully'
    
    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        print('admin_user', admin_user)
        organization_obj = Organization.objects.filter(tenant = admin_user.tenant).first()
        print('organization_obj', organization_obj)
        form.instance.organization = organization_obj
        return super(CreateInvestmentType,self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('administrations:list_investment_type')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateInvestmentTypeDetails(AdminUpdateView):
    model = InvestmentType
    form_class = InvestmentTypeForm
    template_name = 'update_investment_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateInvestmentTypeDetails,self).get_context_data(**kwargs)
        context['modelobj'] = InvestmentType.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateInvestmentTypeDetails, self).get_form_kwargs()
        kw['oldobj'] = InvestmentType.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        investmenttype = InvestmentType.objects.get(pk = kwargs['pk'])
        self.success_message = 'InvestmentType \'' + investmenttype.name + '\' updated sucessfully!'
        return super(UpdateInvestmentTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_investment_type')


@class_view_decorator(login_required)
class ListEmployeeStatus(AdminListView):
    model = EmployeeStatus
    template_name = 'list_employee_status.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = EmployeeStatus.objects.filter(tenant = admin_user.tenant)
        return queryset
    
    def get(self, request, *args, **kwargs):
        return super(ListEmployeeStatus, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEmployeeStatus(AdminCreateView):
    model = EmployeeStatus
    form_class = EmployeeStatusForm
    template_name = 'create_employee_status.html'
    success_message = 'New EmployeeStatus created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateEmployeeStatus, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateEmployeeStatus,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateEmployeeStatus, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_status')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeeStatusDetails(AdminUpdateView):
    model = EmployeeStatus
    form_class = EmployeeStatusForm
    template_name = 'update_employee_status_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeeStatusDetails,self).get_context_data(**kwargs)
        context['modelobj'] = EmployeeStatus.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeeStatusDetails, self).get_form_kwargs()
        kw['oldobj'] = EmployeeStatus.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        employeestatus = EmployeeStatus.objects.get(pk = kwargs['pk'])
        self.success_message = 'EmployeeStatus \'' + employeestatus.name + '\' updated sucessfully!'
        return super(UpdateEmployeeStatusDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_status')


@class_view_decorator(login_required)
class ListEmployeeType(AdminListView):
    model = EmployeeType
    template_name = 'list_employee_type.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = EmployeeType.objects.filter(tenant = admin_user.tenant)
        return queryset
    
    def get(self, request, *args, **kwargs):
        return super(ListEmployeeType, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEmployeeType(AdminCreateView):
    model = EmployeeType
    form_class = EmployeeTypeForm
    template_name = 'create_employee_type.html'
    success_message = 'New EmployeeType created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateEmployeeType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateEmployeeType,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateEmployeeType, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_type')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeeTypeDetails(AdminUpdateView):
    model = EmployeeType
    form_class = EmployeeTypeForm
    template_name = 'update_employee_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeeTypeDetails,self).get_context_data(**kwargs)
        context['modelobj'] = EmployeeType.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeeTypeDetails, self).get_form_kwargs()
        kw['oldobj'] = EmployeeType.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        employeetype = EmployeeType.objects.get(pk = kwargs['pk'])
        self.success_message = 'EmployeeType \'' + employeetype.name + '\' updated sucessfully!'
        return super(UpdateEmployeeTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_type')


'''@class_view_decorator(login_required)
class ListStatus(AdminListView):
    model = Status
    template_name = 'list_status.html'

    def get_queryset(self):
        queryset = Status.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateStatus(AdminCreateView):
    model = Status
    form_class = StatusForm
    template_name = 'create_status.html'
    success_message = 'New Status created successfully'

    def get_success_url(self):
        return reverse_lazy('administrations:list_status')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateStatus(AdminUpdateView):
    model = Status
    form_class = StatusForm
    template_name = 'update_status.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateStatus,self).get_context_data(**kwargs)
        context['modelobj'] = Status.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateStatus, self).get_form_kwargs()
        kw['oldobj'] = Status.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        adminrole = Status.objects.get(pk = kwargs['pk'])
        self.success_message = 'Status \'' + adminrole.name + '\' updated sucessfully!'
        return super(UpdateStatus, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_status')'''


@class_view_decorator(login_required)
class ListSalaryHoldReleaseReason(AdminListView):
    model = SalaryHoldReleaseReason
    template_name = 'list_salary_hold_release_reason.html'

    def get_queryset(self):
        queryset = SalaryHoldReleaseReason.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateSalaryHoldReleaseReason(AdminCreateView):
    model = SalaryHoldReleaseReason
    form_class = SalaryHoldReleaseReasonForm
    template_name = 'create_salary_hold_release_reason.html'
    success_message = 'New Reason created successfully'
    
    def form_valid(self, form):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        print('admin_user', admin_user)
        organization_obj = Organization.objects.filter(tenant = admin_user.tenant).first()
        print('organization_obj...', organization_obj)
        form.instance.organization = organization_obj
        return super(CreateSalaryHoldReleaseReason,self).form_valid(form)

    def get_success_url(self):
        return reverse_lazy('administrations:list_salary_hold_release_reason')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateSalaryHoldReleaseReason(AdminUpdateView):
    model = SalaryHoldReleaseReason
    form_class = SalaryHoldReleaseReasonForm
    template_name = 'update_salary_hold_release_reason.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSalaryHoldReleaseReason,self).get_context_data(**kwargs)
        context['modelobj'] = SalaryHoldReleaseReason.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateSalaryHoldReleaseReason, self).get_form_kwargs()
        kw['oldobj'] = SalaryHoldReleaseReason.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        adminrole = SalaryHoldReleaseReason.objects.get(pk = kwargs['pk'])
        self.success_message = 'Salary Hold Release Reason \'' + adminrole.name + '\' updated sucessfully!'
        return super(UpdateSalaryHoldReleaseReason, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_salary_hold_release_reason')
        
@class_view_decorator(login_required)
class SalaryTemplate(AdminListView):
    model = SalaryHoldReleaseReason
    template_name = 'salary_template.html'


    def get_context_data(self, **kwargs):
        context = super(SalaryTemplate,self).get_context_data(**kwargs)
        list_salary_template = EmployeeSalaryTemplate.objects.all()
        context['list_salary_template'] =  list_salary_template
        return context
        
    def get_queryset(self):
        queryset = SalaryHoldReleaseReason.objects.all()
        return queryset

@class_view_decorator(login_required)
class CreateSalaryTemplate(AdminListView):
    model = SalaryHoldReleaseReason
    template_name = 'create_salary_template.html'

    def get_context_data(self, **kwargs):
        context = super(CreateSalaryTemplate,self).get_context_data(**kwargs)
        context['hide_sidebar'] = True
        earning_type_list = Earning.objects.all()
        deduction_list = Deduction.objects.all()
        earning_map = []
        deduction_map = []
        for obj in earning_type_list:
            earning_map.append({"id":obj.id,"title":obj.earning_type,"key":str(obj.earning_type).replace(" ", ""),"calculation_type":obj.earning_type.calculation_type})
        for obj in deduction_list:
            deduction_map.append({"id":obj.id,"title":obj.get_deduction_type_display,"key":str(obj.display_name_in_payslip).replace(" ", "")})
        context['earning_type_map'] =  earning_map
        context['deduction_list'] = deduction_map
        return context
        
    def get_queryset(self):
        queryset = SalaryHoldReleaseReason.objects.all()
        return queryset

@class_view_decorator(login_required)
class UpdateSalaryTemplate(AdminListView):
    model = SalaryHoldReleaseReason
    template_name = 'update_salary_template.html'


    def get_context_data(self, **kwargs):
        context = super(UpdateSalaryTemplate,self).get_context_data(**kwargs)
        salary_template = EmployeeSalaryTemplate.objects.get(pk = self.kwargs['pk'])
        salary_template_earning_obj = SalaryTemplateEarningMapping.objects.filter(salary_template = salary_template)
        salary_template_deduction_obj = SalaryTemplateDeductionMapping.objects.filter(salary_template = salary_template)
        salary_template_earning_map = []
        salary_template_deduction_map = []
        for obj in salary_template_earning_obj:
            get_earning = Earning.objects.get(pk=obj.earning_id)
            salary_template_earning_map.append({"id":obj.id,"title":get_earning.earning_name,"key":str(get_earning.earning_name).replace(" ", ""),"calculation_type":obj.calculation_type,"salary_template":obj.salary_template,"earning":obj.earning,"calculation_percentage":obj.calculation_percentage,"calculation_amount":obj.calculation_amount,"amount_monthly":obj.amount_monthly,'earning_id':obj.earning_id})
        for obj in salary_template_deduction_obj:
            get_deduction = Deduction.objects.get(pk=obj.deduction_id)
            salary_template_deduction_map.append({"id":obj.id,"title":get_deduction.display_name_in_payslip,"key":str(get_deduction.display_name_in_payslip).replace(" ", ""),"calculation_type":obj.calculation_type,"salary_template":obj.salary_template,"deduction":obj.deduction,"calculation_percentage":obj.calculation_percentage,"calculation_amount":obj.calculation_amount,"amount_monthly":obj.amount_monthly,'deduction_id':obj.deduction_id})
        context['salary_template'] = salary_template
        context['salary_template_earning'] = salary_template_earning_map
        context['salary_template_deduction'] = salary_template_deduction_map
        context['hide_sidebar'] = True
        earning_type_list = Earning.objects.all()
        deduction_list = Deduction.objects.all()
        earning_map = []
        deduction_map = []
        for obj in earning_type_list:
            earning_map.append({"id":obj.id,"title":obj.earning_name,"key":str(obj.earning_name).replace(" ", ""),"calculation_type":obj.earning_type.calculation_type})
        for obj in deduction_list:
            deduction_map.append({"id":obj.id,"title":obj.display_name_in_payslip,"key":str(obj.display_name_in_payslip).replace(" ", "")})
        context['earning_type_map'] =  earning_map
        context['deduction_list'] = deduction_map
        return context
        
    def get_queryset(self):
        queryset = SalaryHoldReleaseReason.objects.all()
        return queryset

# newchanges
@class_view_decorator(login_required)
class ListEmployeePersonalInfo(AdminListView):
    model = PersonalInfo
    template_name = 'list_employee_personal_info.html'

    def get_queryset(self):
        queryset = PersonalInfo.objects.all()
        return queryset

    # def get(self, request, *args, **kwargs):
    #     return super(ListEmployeePersonalInfo, self).get(request, args, kwargs)


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class CreateEmployeePersonalInfo(AdminCreateView):
    model = PersonalInfo
    form_class = EmployeePersonalInfoForm
    template_name = 'create_employee_personal_info.html'
    success_message = 'New Employee Personal Info created successfully'

    # def get_context_data(self, **kwargs):
    #     context = super(CreateEmployeePersonalInfo,self).get_context_data(**kwargs)
    #     personal_info_details = PersonalInfo.objects.filter(is_active = True)
    #     context['form'].fields['upper_department'].queryset =  upper_department_details
    #     return context

    # def get(self, request, *args, **kwargs):
    #     return super(CreateEmployeePersonalInfo, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_employee_personal_info')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeePersonalInfo(AdminUpdateView):
    model = PersonalInfo
    form_class = EmployeePersonalInfoForm
    template_name = 'update_employee_personal_info.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeePersonalInfo,self).get_context_data(**kwargs)
        context['modelobj'] = PersonalInfo.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeePersonalInfo, self).get_form_kwargs()
        kw['oldobj'] = PersonalInfo.objects.get(pk = self.kwargs['pk'])
        return kw

    def post(self, request, *args, **kwargs):
        personalinfo = PersonalInfo.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'PersonalInfo updated sucessfully!'
        return super(UpdateEmployeePersonalInfo, self).post(request, args, kwargs)

    def get_success_url(self):
        personal_info  = PersonalInfo.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':personal_info.employee.pk}) 

#workinfo
@class_view_decorator(login_required)
class ListEmployeeWorkInfo(AdminListView):
    model = WorkInfo
    template_name = 'list_employee_work_info.html'

    def get_queryset(self):
        queryset = WorkInfo.objects.all()
        return queryset

    # def get(self, request, *args, **kwargs):
    #     return super(ListEmployeePersonalInfo, self).get(request, args, kwargs)


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class CreateEmployeeWorkInfo(AdminCreateView):
    model = WorkInfo
    form_class = EmployeeWorkInfoForm
    template_name = 'create_employee_work_info.html'
    success_message = 'New Employee Work Info created successfully'

    # def get_context_data(self, **kwargs):
    #     context = super(CreateEmployeePersonalInfo,self).get_context_data(**kwargs)
    #     personal_info_details = PersonalInfo.objects.filter(is_active = True)
    #     context['form'].fields['upper_department'].queryset =  upper_department_details
    #     return context

    # def get(self, request, *args, **kwargs):
    #     return super(CreateEmployeePersonalInfo, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_employee_work_info')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeeWorkInfo(AdminUpdateView):
    model = WorkInfo
    form_class = EmployeeWorkInfoForm
    template_name = 'update_employee_work_info.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeeWorkInfo,self).get_context_data(**kwargs)
        context['modelobj'] = WorkInfo.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeeWorkInfo, self).get_form_kwargs()
        kw['oldobj'] = WorkInfo.objects.get(pk = self.kwargs['pk'])
        return kw

    def post(self, request, *args, **kwargs):
        workinfo = WorkInfo.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'WorkInfo updated sucessfully!'
        return super(UpdateEmployeeWorkInfo, self).post(request, args, kwargs)

    def get_success_url(self):
        work_info  = WorkInfo.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':work_info.employee.pk})

#employeefile
@class_view_decorator(login_required)
class ListEmployeeFile(AdminListView):
    model = EmployeeFile
    template_name = 'list_employee_file.html'

    def get_queryset(self):
        queryset = EmployeeFile.objects.all()
        return queryset

    # def get(self, request, *args, **kwargs):
    #     return super(ListEmployeePersonalInfo, self).get(request, args, kwargs)


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class CreateEmployeeFile(AdminCreateView):
    model = EmployeeFile
    form_class = EmployeeFileForm
    template_name = 'create_employee_file.html'
    success_message = 'New Employee File created successfully'

    # def get_context_data(self, **kwargs):
    #     context = super(CreateEmployeePersonalInfo,self).get_context_data(**kwargs)
    #     personal_info_details = PersonalInfo.objects.filter(is_active = True)
    #     context['form'].fields['upper_department'].queryset =  upper_department_details
    #     return context

    # def get(self, request, *args, **kwargs):
    #     return super(CreateEmployeePersonalInfo, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse('administrations:list_employee_file')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeeFile(AdminUpdateView):
    model = EmployeeFile
    form_class = EmployeeFileForm
    template_name = 'update_employee_file.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeeFile,self).get_context_data(**kwargs)
        context['modelobj'] = EmployeeFile.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeeFile, self).get_form_kwargs()
        kw['oldobj'] = EmployeeFile.objects.get(pk = self.kwargs['pk'])
        return kw

    def post(self, request, *args, **kwargs):
        workinfo = EmployeeFile.objects.get(pk = self.kwargs['pk'])
        self.success_message = 'EmployeeFile updated sucessfully!'
        return super(UpdateEmployeeFile, self).post(request, args, kwargs)

    def get_success_url(self):
        employeefile  = EmployeeFile.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':employeefile.employee.pk})


@class_view_decorator(login_required)
class ListSummary(AdminListView):
    model = Summary
    template_name = 'list_summary.html'

    def get_queryset(self):
        queryset = Summary.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateSummary(AdminCreateView):
    model = Summary
    form_class = SummaryForm
    template_name = 'create_summary.html'
    success_message = 'New Summary created successfully'

    def get_success_url(self):
        return reverse_lazy('administrations:list_summary')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateSummaryDetails(AdminUpdateView):
    model = Summary
    form_class = SummaryForm
    template_name = 'update_summary_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSummaryDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Summary.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateSummaryDetails, self).get_form_kwargs()
        kw['oldobj'] = Summary.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        summary = Summary.objects.get(pk = kwargs['pk'])
        self.success_message = 'Summary updated sucessfully!'
        return super(UpdateSummaryDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        summary = Summary.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':summary.employee.pk})


@class_view_decorator(login_required)
class ListWorkExperience(AdminListView):
    model = WorkExperience
    template_name = 'list_work_experience.html'

    def get_queryset(self):
        queryset = WorkExperience.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateWorkExperience(AdminCreateView):
    model = WorkExperience
    form_class = WorkExperienceForm
    template_name = 'create_work_experience.html'
    success_message = 'New WorkExperience created successfully'

    def get_success_url(self):
        return reverse_lazy('administrations:list_work_experience')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateWorkExperienceDetails(AdminUpdateView):
    model = WorkExperience
    form_class = WorkExperienceForm
    template_name = 'update_work_experience_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateWorkExperienceDetails,self).get_context_data(**kwargs)
        context['modelobj'] = WorkExperience.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateWorkExperienceDetails, self).get_form_kwargs()
        kw['oldobj'] = WorkExperience.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        workingexperience = WorkExperience.objects.get(pk = kwargs['pk'])
        self.success_message = 'WorkExperience updated sucessfully!'
        return super(UpdateWorkExperienceDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        work_experience  = WorkExperience.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':work_experience.employee.pk})


@class_view_decorator(login_required)
class ListEducation(AdminListView):
    model = Education
    template_name = 'list_education.html'

    def get_queryset(self):
        queryset = Education.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEducation(AdminCreateView):
    model = Education
    form_class = EducationForm
    template_name = 'create_education.html'
    success_message = 'New Education created successfully'

    def get_success_url(self):
        return reverse_lazy('administrations:list_education')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEducationDetails(AdminUpdateView):
    model = Education
    form_class = EducationForm
    template_name = 'update_education_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEducationDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Education.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEducationDetails, self).get_form_kwargs()
        kw['oldobj'] = Education.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        education = Education.objects.get(pk = kwargs['pk'])
        self.success_message = 'Education updated sucessfully!'
        return super(UpdateEducationDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        education  = Education.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':education.employee.pk})


@class_view_decorator(login_required)
class ListDependent(AdminListView):
    model = Dependent
    template_name = 'list_dependent.html'

    def get_queryset(self):
        queryset = Dependent.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateDependent(AdminCreateView):
    model = Dependent
    form_class = DependentForm
    template_name = 'create_dependent.html'
    success_message = 'New Dependent created successfully'

    def get_success_url(self):
        return reverse_lazy('administrations:list_dependent')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateDependentDetails(AdminUpdateView):
    model = Dependent
    form_class = DependentForm
    template_name = 'update_dependent_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateDependentDetails,self).get_context_data(**kwargs)
        context['modelobj'] = Dependent.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateDependentDetails, self).get_form_kwargs()
        kw['oldobj'] = Dependent.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        dependent = Dependent.objects.get(pk = kwargs['pk'])
        self.success_message = 'Dependent updated sucessfully!'
        return super(UpdateDependentDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        dependent  = Dependent.objects.get(pk = self.kwargs['pk'])
        return reverse('administrations:update_employee', kwargs={'pk':dependent.employee.pk})


@class_view_decorator(login_required)
class ListLeaveType(AdminListView):
    model = LeaveType
    template_name = 'list_leave_type.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        queryset = LeaveType.objects.filter(tenant = admin_user.tenant)
        return queryset
    
    def get(self, request, *args, **kwargs):
        return super(ListLeaveType, self).get(request, args, kwargs)


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateLeaveType(AdminCreateView):
    model = LeaveType
    form_class = LeaveTypeForm
    template_name = 'create_leave_type.html'
    success_message = 'New LeaveType created successfully'
    
    def get_form_kwargs(self):
        kw = super(CreateLeaveType, self).get_form_kwargs()
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        return kw

    def form_valid(self, form):
        adminobj = Administrator.objects.get(pk = self.request.user.id)
        form.instance.tenant = adminobj.tenant
        return super(CreateLeaveType,self).form_valid(form)
    
    def get(self, request, *args, **kwargs):
        return super(CreateLeaveType, self).get(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_leave_type')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateLeaveTypeDetails(AdminUpdateView):
    model = LeaveType
    form_class = LeaveTypeForm
    template_name = 'update_leave_type_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateLeaveTypeDetails,self).get_context_data(**kwargs)
        context['modelobj'] = LeaveType.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateLeaveTypeDetails, self).get_form_kwargs()
        kw['oldobj'] = LeaveType.objects.get(pk = self.kwargs['pk'])
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        kw['tenant'] = admin_user.tenant
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        leavetype = Summary.objects.get(pk = kwargs['pk'])
        self.success_message = 'LeaveType updated sucessfully!'
        return super(UpdateLeaveTypeDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_leave_type')


@class_view_decorator(login_required)
class ListEmployeeLeaveRequest(AdminListView):
    model = EmployeeLeaveRequest
    template_name = 'list_employee_leave_request.html'

    def get_queryset(self):
        queryset = EmployeeLeaveRequest.objects.all()
        return queryset


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEmployeeLeaveRequest(AdminCreateView):
    model = EmployeeLeaveRequest
    form_class = EmployeeLeaveRequesttForm
    template_name = 'create_employee_leave_request.html'
    success_message = 'New EmployeeLeaveRequest created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateEmployeeLeaveRequest,self).get_context_data(**kwargs)
        context['modelobj']  = EmployeeLeaveRequest.objects.all()
        return context

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_leave_request')


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployeeLeaveRequestDetails(AdminUpdateView):
    model = EmployeeLeaveRequest
    form_class = EmployeeLeaveRequesttForm
    template_name = 'update_employee_leave_request_details.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployeeLeaveRequestDetails,self).get_context_data(**kwargs)
        context['modelobj'] = EmployeeLeaveRequest.objects.get(pk = self.kwargs['pk'])
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployeeLeaveRequestDetails, self).get_form_kwargs()
        kw['oldobj'] = EmployeeLeaveRequest.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        employeeleaverequest = EmployeeLeaveRequest.objects.get(pk = kwargs['pk'])
        self.success_message = 'EmployeeLeaveRequest updated sucessfully!'
        return super(UpdateEmployeeLeaveRequestDetails, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee_leave_request')

#employee
@class_view_decorator(login_required)
class ListEmployee(AdminListView):
    model = HCMSUser
    template_name = 'list_employee.html'

    def get_queryset(self):
        admin_user = Administrator.objects.get(pk=self.request.user.id)
        oragnization_obj = Organization.objects.filter(tenant = admin_user.tenant).first()
        queryset = HCMSUser.objects.filter(organization = oragnization_obj, is_employee = True, is_active = True)
        return queryset       

@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class CreateEmployee(AdminCreateView):
    model = HCMSUser
    form_class = EmployeeForm
    template_name = 'create_employee.html'
    success_message = 'New Employee created successfully'
    
    def get_context_data(self, **kwargs):
        context = super(CreateEmployee,self).get_context_data(**kwargs)
        context['modelobj']  = HCMSUser.objects.all()
        genderobj = Gender.objects.all()
        gender_choices = []
        gender_choices.append(['0','-------'])
        for gender in genderobj:
            if gender:
                gender_choices.append([gender.id, gender.name])
        context['form'].fields['gender'].choices =  gender_choices
        stateobj = State.objects.all()
        state_choices = []
        state_choices.append(['0','-------'])
        for state in stateobj:
            if state:
                state_choices.append([state.id, state.name])
        context['form'].fields['state'].choices =  state_choices
        return context

    def get_success_url(self):
        gender = request.POST.get('gender')
        state = request.POST.get('state')
        birth_date = request.POST.get('birth_date')
        genderobj = Gender.objects.get(pk = gender)
        print('genderobj', genderobj)
        stateobj = State.objects.get(pk = state)
        print('stateobj', stateobj)
        # self.gender = request.POST.get('gender', '')
        employeeobj = Employee.objects.get(pk = self.object.pk)
        print('empppp', employeeobj)
        personal_info = PersonalInfo(employee = employeeobj, state = stateobj, gender = genderobj, birth_date = birth_date)
        personal_info.save()
        return reverse_lazy('administrations:list_employee')        


@class_view_decorator(login_required)
@class_view_decorator(csrf_exempt)
class UpdateEmployee(AdminUpdateView):
    model = HCMSUser
    form_class = EmployeeForm
    template_name = 'update_employee.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateEmployee,self).get_context_data(**kwargs)
        context['modelobj'] = HCMSUser.objects.get(pk = self.kwargs['pk'])
        personal_info = PersonalInfo.objects.all()
        Summary_list = Summary.objects.all()
        work_experience_list = WorkExperience.objects.all()
        work_info_list = WorkInfo.objects.all()
        education_list = Education.objects.all()
        dependent_list = Dependent.objects.all()
        employee_file_list = EmployeeFile.objects.all()
        context['Summary_list'] = Summary_list
        context['personal_info'] = personal_info
        context['work_experience_list'] = work_experience_list
        context['work_info_list'] = work_info_list
        context['education_list'] = education_list
        context['dependent_list'] = dependent_list
        context['employee_file_list'] = employee_file_list
        return context

    def get_form_kwargs(self):
        kw = super(UpdateEmployee, self).get_form_kwargs()
        kw['oldobj'] = HCMSUser.objects.get(pk = self.kwargs['pk'])
        kw['is_update'] = True
        return kw

    def post(self, request, *args, **kwargs):
        employee = HCMSUser.objects.get(pk = kwargs['pk'])
        self.success_message = 'Employee updated sucessfully!'
        return super(UpdateEmployee, self).post(request, args, kwargs)

    def get_success_url(self):
        return reverse_lazy('administrations:list_employee') 


@class_view_decorator(csrf_exempt)
@class_view_decorator(login_required)
class SaveSalaryTemplate(View):

    def post(self, request, *args, **kwargs):
        salary_template = json.loads(request.POST['salary_template'])
        earnings = json.loads(request.POST['earnings'])
        deductions = json.loads(request.POST['deduction'])
        salary_template_obj =  EmployeeSalaryTemplate(template_name = salary_template['template_name'],description=salary_template['description'],annual_ctc=salary_template['annual_ctc'])
        salary_template_obj.save()
        for obj in earnings:
            earning = Earning.objects.get(pk = obj['earning'])
            salary_template_earning_obj = SalaryTemplateEarningMapping(salary_template = salary_template_obj,earning=earning,calculation_type=obj['calculation_type'],calculation_percentage=obj['calculation_percentage'],calculation_amount=obj['calculation_amount'],amount_monthly=obj['amount_monthly'])
            salary_template_earning_obj.save()
        for obj in deductions:
            deduction = Deduction.objects.get(pk = obj['deduction'])
            salary_template_deduction_obj = SalaryTemplateDeductionMapping(salary_template = salary_template_obj,deduction=deduction,calculation_type=obj['calculation_type'],calculation_percentage=obj['calculation_percentage'],calculation_amount=obj['calculation_amount'],amount_monthly=obj['amount_monthly'])
            salary_template_deduction_obj.save()
        response_str = '<response>'
        response_str += '</response>'
        return HttpResponse(response_str, content_type='text/xml')
        