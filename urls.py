from django.conf import settings
from django.conf.urls import include, url

from . import views

urlpatterns = [
    url(r'^$', views.HomePage.as_view(), name='home_page'),
    url(r'^getcalldata/(?P<sla_type>[1-2])/(?P<sla_status>[0-1])/(?P<month_id>[0-5])/(?P<vendor_id>[0-5])/(?P<branch_id>[0-9]+)/(?P<customer_id>[0-9]+)/(?P<queue_id>[0-9]+)/(?P<customer_group_id>[0-9]+)/$', views.GetCallData.as_view(), name='get_call_data'),
    url(r'^myprofile/$', views.MyProfile.as_view(), name='my_profile'),
    url(r'^mypassword/$', views.ResetMyPassword.as_view(), name='reset_my_password'),
    url(r'^displaycall/(?P<pk>[0-9]+)/$', views.DisplayCallTicketDetails.as_view(), name='display_call_ticket_details'),
    url(r'^createcall/$', views.CreateCallTicket.as_view(), name='create_call'),
    url(r'^editcalldetails/(?P<pk>[0-9]+)/$', views.EditCallDetails.as_view(), name='edit_call_details'),
    url(r'^displaycalldetails/(?P<pk>[0-9]+)/$', views.DisplayCallDetails.as_view(), name='display_call_details'),
    url(r'^displaycallcustomer/(?P<pk>[0-9]+)/$', views.DisplayCallCustomerDetails.as_view(), name='display_call_customer_details'),
    url(r'^displaycallmachine/(?P<pk>[0-9]+)/$', views.DisplayCallMachineDetails.as_view(), name='display_call_machine_details'),
    url(r'^displaycallengineerfeedback/(?P<pk>[0-9]+)/$', views.DisplayCallEngineerFeedbackDetails.as_view(), name='display_call_engineer_feedback_details'),
    url(r'^editcallcustomerdetails/(?P<pk>[0-9]+)/$', views.EditCallCustomerDetails.as_view(), name='edit_call_customer_details'),
    url(r'^editcallmachinedetails/(?P<pk>[0-9]+)/$', views.EditCallMachineDetails.as_view(), name='edit_call_machine_details'),
    url(r'^createcallengineerfeedbackdetail/(?P<ticket_id>[0-9]+)/$', views.CreateCallEngineerFeedbackDetail.as_view(), name='create_call_engineer_feedback_detail'),
    url(r'^editcallengineerfeedbackdetails/(?P<pk>[0-9]+)/$', views.EditCallEngineerFeedbackDetails.as_view(), name='edit_call_engineer_feedback_details'),
    url(r'^displaycalldetails/(?P<pk>[0-9]+)/$', views.DisplayCallDetails.as_view(), name='display_call_details'),
    url(r'^listcalltickets/$', views.ListCallTicketDetails.as_view(), name='list_call_tickets'),
    url(r'^listageingcalltickets/$', views.ListAgeingCallDetails.as_view(), name='list_call_ageing_tickets'),
    url(r'^addcallnotes/(?P<ticket_id>[0-9]+)/$', views.CreateCallNotesDetails.as_view(), name='create_call_notes'),
    url(r'^listcallnotes/(?P<ticket_id>[0-9]+)/$', views.ListCallNotes.as_view(), name='list_call_notes'),
    url(r'^editcallnote/(?P<pk>[0-9]+)/$', views.EditCallNotesDetails.as_view(), name='edit_call_note'),
    url(r'^listcallchangeaudits/(?P<ticket_id>[0-9]+)/$', views.ListTicketChangesAudit.as_view(), name='list_call_change_audits'),
    url(r'^listcallstatustrack/(?P<ticket_id>[0-9]+)/$', views.ListTicketStatusTrack.as_view(), name='list_call_status_track'),
    url(r'^dataupload/$', views.DataUpload.as_view(), name='data_upload'),
    url(r'^addcalllineitem/(?P<ticket_id>[0-9]+)/$', views.CreateCallLineItem.as_view(), name='create_call_line_item'),
    url(r'^listcalllineitems/(?P<ticket_id>[0-9]+)/$', views.ListCallLineItems.as_view(), name='list_call_line_items'),
    url(r'^editcalllineitem/(?P<pk>[0-9]+)/$', views.EditCallLineItemDetails.as_view(), name='edit_call_line_item'),
    url(r'^addcalldocument/(?P<ticket_id>[0-9]+)/$', views.CreateCallDocumentDetails.as_view(), name='create_call_document'),
    url(r'^listcalldocuments/(?P<ticket_id>[0-9]+)/$', views.ListCallDocuments.as_view(), name='list_call_documents'),
    url(r'^editcalldocument/(?P<pk>[0-9]+)/$', views.EditCallDocumentDetails.as_view(), name='edit_call_document'),
    url(r'^listmachines/$', views.ListMachines.as_view(), name='list_machines'),
    url(r'^displaymachinedetails/(?P<pk>[0-9]+)/$', views.DisplayMachineDetails.as_view(), name='display_machine_details'),
    url(r'^createmachine/$', views.CreateMachine.as_view(), name='create_machine'),
    url(r'^updatemachine/(?P<pk>[0-9]+)/$', views.UpdateMachineDetails.as_view(), name='update_machine'),
    url(r'^listcustomers/$', views.ListCustomers.as_view(), name='list_customers'),
    url(r'^displaycustomerdetails/(?P<pk>[0-9]+)/$', views.DisplayCustomerDetails.as_view(), name='display_customer_details'),
    url(r'^createcustomer/$', views.CreateCustomer.as_view(), name='create_customer'),
    url(r'^updatecustomer/(?P<pk>[0-9]+)/$', views.UpdateCustomerDetails.as_view(), name='update_customer'),
    url(r'^listskills/$', views.ListSkills.as_view(), name='list_skills'),
    url(r'^displayskilldetails/(?P<pk>[0-9]+)/$', views.DisplaySkillDetails.as_view(), name='display_skill_details'),
    url(r'^createskill/$', views.CreateSkill.as_view(), name='create_skill'),
    url(r'^updateskill/(?P<pk>[0-9]+)/$', views.UpdateSkillDetails.as_view(), name='update_skill'),
    url(r'^listbranches/(?P<vendor_id>[0-9]+)/$', views.ListBranches.as_view(), name='list_branches'),
    url(r'^createbranch/(?P<vendor_id>[0-9]+)/$', views.CreateBranch.as_view(), name='create_branch'),
    url(r'^displaybranchdetails/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.DisplayBranchDetails.as_view(), name='display_branch_details'),
    url(r'^updatebranch/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateBranchDetails.as_view(), name='update_branch'),
    url(r'^listengineers/$', views.ListEngineers.as_view(), name='list_engineers'),
    url(r'^createengineer/$', views.CreateEngineer.as_view(), name='create_engineer'),
    url(r'^displayengineerdetails/(?P<pk>[0-9]+)/$', views.DisplayEngineerDetails.as_view(), name='display_engineer_details'),
    url(r'^updateengineer/(?P<pk>[0-9]+)/$', views.UpdateEngineerDetails.as_view(), name='update_engineer'),
    url(r'^listcountry/$', views.ListCountry.as_view(), name='list_country'),
    url(r'^createcountry/$', views.CreateCountry.as_view(), name='create_country'),
    url(r'^displaycountrydetails/(?P<pk>[0-9]+)/$', views.DisplayCountryDetails.as_view(), name='display_country_details'),
    url(r'^updatecountry/(?P<pk>[0-9]+)/$', views.UpdateCountryDetails.as_view(), name='update_country'),
    url(r'^liststate/$', views.ListState.as_view(), name='list_state'),
    url(r'^createstate/$', views.CreateState.as_view(), name='create_state'),
    url(r'^displaystatedetails/(?P<pk>[0-9]+)/$', views.DisplayStateDetails.as_view(), name='display_state_details'),
    url(r'^updatestate/(?P<pk>[0-9]+)/$', views.UpdateStateDetails.as_view(), name='update_state'),
    url(r'^listvendor/$', views.ListVendor.as_view(), name='list_vendor'),
    url(r'^createvendor/$', views.CreateVendor.as_view(), name='create_vendor'),
    url(r'^displayvendordetails/(?P<pk>[0-9]+)/$', views.DisplayVendorDetails.as_view(), name='display_vendor_details'),
    url(r'^updatevendor/(?P<pk>[0-9]+)/$', views.UpdateVendorDetails.as_view(), name='update_vendor'),
    url(r'^listregion/$', views.ListRegion.as_view(), name='list_region'),
    url(r'^createregion/$', views.CreateRegion.as_view(), name='create_region'),
    url(r'^displayregiondetails/(?P<pk>[0-9]+)/$', views.DisplayRegionDetails.as_view(), name='display_region_details'),
    url(r'^updateregion/(?P<pk>[0-9]+)/$', views.UpdateRegionDetails.as_view(), name='update_region'),
    url(r'^listwarrantytype/$', views.ListWarrantyType.as_view(), name='list_warranty_type'),
    url(r'^createwarrantytype/$', views.CreateWarrantyType.as_view(), name='create_warranty_type'),
    url(r'^displaywarrantytypedetails/(?P<pk>[0-9]+)/$', views.DisplayWarrantyTypeDetails.as_view(), name='display_warranty_type_details'),
    url(r'^updatewarrantytype/(?P<pk>[0-9]+)/$', views.UpdateWarrantyTypeDetails.as_view(), name='update_warranty_type'),
    url(r'^listcalltype/(?P<vendor_id>[0-9]+)/$', views.ListCallType.as_view(), name='list_call_type'),
    url(r'^createcalltype/(?P<vendor_id>[0-9]+)/$', views.CreateCallType.as_view(), name='create_call_type'),
    url(r'^displaycalltypedetails/(?P<pk>[0-9]+)/$', views.DisplayCallTypeDetails.as_view(), name='display_call_type_details'),
    url(r'^updatecalltype/(?P<pk>[0-9]+)/$', views.UpdateCallTypeDetails.as_view(), name='update_call_type'),
    url(r'^listtickettype/$', views.ListTicketType.as_view(), name='list_ticket_type'),
    url(r'^createtickettype/$', views.CreateTicketType.as_view(), name='create_ticket_type'),
    url(r'^displaytickettypedetails/(?P<pk>[0-9]+)/$', views.DisplayTicketTypeDetails.as_view(), name='display_ticket_type_details'),
    url(r'^updatetickettype/(?P<pk>[0-9]+)/$', views.UpdateTicketTypeDetails.as_view(), name='update_ticket_type'),
    url(r'^listlineitemcategory/$', views.ListLineItemCategory.as_view(), name='list_lineitem_category'),
    url(r'^createlineitemcategory/$', views.CreateLineItemCategory.as_view(), name='create_lineitem_category'),
    url(r'^displaylineitemcategorydetails/(?P<pk>[0-9]+)/$', views.DisplayLineItemCategoryDetails.as_view(), name='display_lineitem_category_details'),
    url(r'^updatelineitemcategory/(?P<pk>[0-9]+)/$', views.UpdateLineItemCategoryDetails.as_view(), name='update_lineitem_category'),
    url(r'^listmachinetype/$', views.ListMachineType.as_view(), name='list_machine_type'),
    url(r'^createmachinetype/$', views.CreateMachineType.as_view(), name='create_machine_type'),
    url(r'^displaymachinetypedetails/(?P<pk>[0-9]+)/$', views.DisplayMachineTypeDetails.as_view(), name='display_machine_type_details'),
    url(r'^updatemachinetype/(?P<pk>[0-9]+)/$', views.UpdateMachineTypeDetails.as_view(), name='update_machine_type'),
    url(r'^listmachinemake/$', views.ListMachineMake.as_view(), name='list_machine_make'),
    url(r'^createmachinemake/$', views.CreateMachineMake.as_view(), name='create_machine_make'),
    url(r'^displaymachinemakedetails/(?P<pk>[0-9]+)/$', views.DisplayMachineMakeDetails.as_view(), name='display_machine_make_details'),
    url(r'^updatemachinemake/(?P<pk>[0-9]+)/$', views.UpdateMachineMakeDetails.as_view(), name='update_machine_make'),
    url(r'^listadminrole/$', views.ListAdminRole.as_view(), name='list_admin_role'),
    url(r'^createadminrole/$', views.CreateAdminRole.as_view(), name='create_admin_role'),
    url(r'^displayadminroledetails/(?P<pk>[0-9]+)/$', views.DisplayAdminRoleDetails.as_view(), name='display_admin_role_details'),
    url(r'^updateadminrole/(?P<pk>[0-9]+)/$', views.UpdateAdminRoleDetails.as_view(), name='update_admin_role'),
    url(r'^listlocation/(?P<vendor_id>[0-9]+)/$', views.ListLocation.as_view(), name='list_location'),
    url(r'^createlocation/(?P<vendor_id>[0-9]+)/$', views.CreateLocation.as_view(), name='create_location'),
    url(r'^updatelocation/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateLocationDetails.as_view(), name='update_location'),
    url(r'^listdesignation/$', views.ListDesignation.as_view(), name='list_designation'),
    url(r'^createdesignation/$', views.CreateDesignation.as_view(), name='create_designation'),
    url(r'^updatedesignation/(?P<pk>[0-9]+)/$', views.UpdateDesignationDetails.as_view(), name='update_designation'),
    url(r'^listcallstatus/$', views.ListCallStatus.as_view(), name='list_call_status'),
    url(r'^createcallstatus/$', views.CreateCallStatus.as_view(), name='create_call_status'),
    url(r'^updatecallstatus/(?P<pk>[0-9]+)/$', views.UpdateCallStatusDetails.as_view(), name='update_call_status'),
    url(r'^listreasoncode/$', views.ListReasonCode.as_view(), name='list_reason_code'),
    url(r'^createreasoncode/$', views.CreateReasonCode.as_view(), name='create_reason_code'),
    url(r'^updatereasoncode/(?P<pk>[0-9]+)/$', views.UpdateReasonCodeDetails.as_view(), name='update_reason_code'),
    url(r'^listlineitemstatus/$', views.ListLineItemStatus.as_view(), name='list_lineitem_status'),
    url(r'^createlineitemstatus/$', views.CreateLineItemStatus.as_view(), name='create_lineitem_status'),
    url(r'^updatelineitemstatus/(?P<pk>[0-9]+)/$', views.UpdateLineItemStatusDetails.as_view(), name='update_lineitem_status'),
    url(r'^listlineitemdispositioncode/$', views.ListLineItemDispositionCode.as_view(), name='list_lineitem_disposition_code'),
    url(r'^createlineitemdispositioncode/$', views.CreateLineItemDispositionCode.as_view(), name='create_lineitem_disposition_code'),
    url(r'^updatelineitemdispositioncode/(?P<pk>[0-9]+)/$', views.UpdateLineItemDispositionCodeDetails.as_view(), name='update_lineitem_disposition_code'),
    url(r'^listuserstatus/$', views.ListUserStatus.as_view(), name='list_user_status'),
    url(r'^createuserstatus/$', views.CreateUserStatus.as_view(), name='create_user_status'),
    url(r'^updateuserstatus/(?P<pk>[0-9]+)/$', views.UpdateUserStatusDetails.as_view(), name='update_user_status'),
    url(r'^listcustomerstatus/$', views.ListCustomerStatus.as_view(), name='list_customer_status'),
    url(r'^createcustomerstatus/$', views.CreateCustomerStatus.as_view(), name='create_customer_status'),
    url(r'^updatecustomerstatus/(?P<pk>[0-9]+)/$', views.UpdateCustomerStatusDetails.as_view(), name='update_customer_status'),
    url(r'^listassetstatus/$', views.ListAssetStatus.as_view(), name='list_asset_status'),
    url(r'^createassetstatus/$', views.CreateAssetStatus.as_view(), name='create_asset_status'),
    url(r'^updateassetstatus/(?P<pk>[0-9]+)/$', views.UpdateAssetStatusDetails.as_view(), name='update_asset_status'),
    url(r'^listmachinemodel/$', views.ListMachineModel.as_view(), name='list_machine_model'),
    url(r'^createmachinemodel/$', views.CreateMachineModel.as_view(), name='create_machine_model'),
    url(r'^updatemachinemodel/(?P<pk>[0-9]+)/$', views.UpdateMachineModelDetails.as_view(), name='update_machine_model'),
    url(r'^listprojects/$', views.ListProjects.as_view(), name='list_projects'),
    url(r'^createproject/$', views.CreateProject.as_view(), name='create_project'),
    url(r'^updateproject/(?P<pk>[0-9]+)/$', views.UpdateProjectDetails.as_view(), name='update_project'),
    url(r'^listadministrators/$', views.ListAdministrators.as_view(), name='list_administrators'),
    url(r'^createadministrator/$', views.CreateAdministrator.as_view(), name='create_administrator'),
    url(r'^updateadministrator/(?P<pk>[0-9]+)/$', views.UpdateAdministratorDetails.as_view(), name='update_administrator'),
    url(r'changepassword/(?P<url_id>[0-9a-f]+)/$', views.ChangePassword.as_view(), name='change_password'),
    url(r'^listcountryvendoremail/(?P<vendor_id>[0-9]+)/$', views.ListCountryVendorEmail.as_view(), name='list_country_vendor_email'),
    url(r'^createcountryvendoremail/(?P<vendor_id>[0-9]+)/$', views.CreateCountryVendorEmail.as_view(), name='create_country_vendor_email'),
    url(r'^updatecountryvendoremail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateCountryVendorEmailDetails.as_view(), name='update_country_vendor_email'),
    url(r'^liststatevendoremail/(?P<vendor_id>[0-9]+)/$', views.ListStateVendorEmail.as_view(), name='list_state_vendor_email'),
    url(r'^createstatevendoremail/(?P<vendor_id>[0-9]+)/$', views.CreateStateVendorEmail.as_view(), name='create_state_vendor_email'),
    url(r'^updatestatevendoremail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateStateVendorEmailDetails.as_view(), name='update_state_vendor_email'),
    url(r'^listregionvendoremail/(?P<vendor_id>[0-9]+)/$', views.ListRegionVendorEmail.as_view(), name='list_region_vendor_email'),
    url(r'^createregionvendoremail/(?P<vendor_id>[0-9]+)/$', views.CreateRegionVendorEmail.as_view(), name='create_region_vendor_email'),
    url(r'^updateregionvendoremail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateRegionVendorEmailDetails.as_view(), name='update_region_vendor_email'),
    url(r'^listbranchvendoremail/(?P<vendor_id>[0-9]+)/$', views.ListBranchVendorEmail.as_view(), name='list_branch_vendor_email'),
    url(r'^createbranchvendoremail/(?P<vendor_id>[0-9]+)/$', views.CreateBranchVendorEmail.as_view(), name='create_branch_vendor_email'),
    url(r'^updatebranchvendoremail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateBranchVendorEmailDetails.as_view(), name='update_branch_vendor_email'),    
    url(r'^listlocationvendoremail/(?P<vendor_id>[0-9]+)/$', views.ListLocationVendorEmail.as_view(), name='list_location_vendor_email'),
    url(r'^createlocationvendoremail/(?P<vendor_id>[0-9]+)/$', views.CreateLocationVendorEmail.as_view(), name='create_location_vendor_email'),
    url(r'^updatelocationvendoremail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateLocationVendorEmailDetails.as_view(), name='update_location_vendor_email'),
    url(r'^listqueuevendoremail/(?P<vendor_id>[0-9]+)/$', views.ListQueueVendorEmail.as_view(), name='list_queue_vendor_email'),
    url(r'^createqueuevendoremail/(?P<vendor_id>[0-9]+)/$', views.CreateQueueVendorEmail.as_view(), name='create_queue_vendor_email'),
    url(r'^updatequeuevendoremail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateQueueVendorEmailDetails.as_view(), name='update_queue_vendor_email_details'),    
    url(r'^listautoemail/(?P<vendor_id>[0-9]+)/$', views.ListAutoEmail.as_view(), name='list_auto_email'),
    url(r'^createautoemail/(?P<vendor_id>[0-9]+)/$', views.CreateAutoEmail.as_view(), name='create_auto_email'),
    url(r'^updateautoemail/(?P<pk>[0-9]+)/(?P<vendor_id>[0-9]+)/$', views.UpdateAutoEmailDetails.as_view(), name='update_auto_email'),
    url(r'^resetpassword/(?P<pk>[0-9]+)/$', views.ResetPassword.as_view(), name='reset_password'),
    url(r'^createseveritylevel/(?P<customer_id>[0-9]+)/$', views.CreateSeverityLevel.as_view(), name='create_severity_level'),
    url(r'^updateseveritylevel/(?P<pk>[0-9]+)/$', views.UpdateSeverityLevelDetails.as_view(), name='update_severity_level'),
    url(r'^createtier/(?P<customer_id>[0-9]+)/$', views.CreateTier.as_view(), name='create_tier'),
    url(r'^updatetier/(?P<pk>[0-9]+)/$', views.UpdateTierDetails.as_view(), name='update_tier'),
    url(r'^createholiday/(?P<customer_id>[0-9]+)/$', views.CreateHoliday.as_view(), name='create_holiday'),
    url(r'^updateholiday/(?P<pk>[0-9]+)/$', views.UpdateHolidayDetails.as_view(), name='update_holiday'),
    url(r'^deleteholidaydate/(?P<pk>[0-9]+)/$', views.DeleteHolidayDate.as_view(), name='delete_holiday_date'),
    url(r'^createsla/(?P<customer_id>[0-9]+)/$', views.CreateSLA.as_view(), name='create_sla'),
    url(r'^updatesla/(?P<pk>[0-9]+)/$', views.UpdateSLADetails.as_view(), name='update_sla'),
    url(r'^deletesla/(?P<pk>[0-9]+)/$', views.DeleteSLA.as_view(), name='delete_sla'),
    url(r'^createdepartment/(?P<customer_id>[0-9]+)/$', views.CreateDepartment.as_view(), name='create_department'),
    url(r'^updatedepartment/(?P<pk>[0-9]+)/$', views.UpdateDepartmentDetails.as_view(), name='update_department'),
    url(r'^createlocationtype/(?P<customer_id>[0-9]+)/$', views.CreateLocationType.as_view(), name='create_location_type'),
    url(r'^updatelocationtype/(?P<pk>[0-9]+)/$', views.UpdateLocationTypeDetails.as_view(), name='update_location_type'),
    url(r'^listvendorsupport/$', views.ListVendorSupport.as_view(), name='list_vendor_support'),
    url(r'^createvendorsupport/$', views.CreateVendorSupport.as_view(), name='create_vendor_support'),
    url(r'^updatevendorsupport/(?P<pk>[0-9]+)/$', views.UpdateVendorSupportDetails.as_view(), name='update_vendor_support'),
    url(r'^getunreadnotifications/$', views.GetUnreadNotifications.as_view(),name='get_unread_notifications'),
    url(r'^shownotifications/$', views.ShowNotifications.as_view(),name='show_notifications'),
    url(r'^markasreadunread/(?P<notification_id>\d+)/$', views.MarkAsReadUnread.as_view(), name='mark_as_read_unread'),
    url(r'^listengineerreport/(?P<report_type>[a-z]+)/$', views.ListEngineerReport.as_view(), name='list_engineer_report'),
    url(r'^userloginreport/$', views.UserLoginReport.as_view(), name='user_login_report'),
    url(r'^activeusersreport/$', views.ActiveUsersReport.as_view(), name='active_users_report'),
    url(r'^autoassignengineer/$', views.AutoAssignEngineer.as_view(), name='auto_assign_engineer'),
    url(r'^recallengineer/(?P<pk>[0-9]+)/$', views.RecallEngineer.as_view(), name='recall_engineer'),
    url(r'^listcallclassification/(?P<vendor_id>[0-9]+)/$', views.ListCallClassification.as_view(), name='list_call_classification'),
    url(r'^createcallclassification/(?P<vendor_id>[0-9]+)/$', views.CreateCallClassification.as_view(), name='create_call_classification'),
    url(r'^updatecallclassfication/(?P<pk>[0-9]+)/$', views.UpdateCallClassificationDetails.as_view(), name='update_call_classification'),
    url(r'^getopenticketdata/(?P<vendor_id>[0-5])/(?P<branch_id>[0-9]+)/(?P<customer_id>[0-9]+)/(?P<queue_id>[0-9]+)/(?P<customer_group_id>[0-9]+)/$', views.GetOpenTicketData.as_view(), name='get_open_ticket_data'),
    url(r'^getassetdata/(?P<vendor_id>[0-5])/(?P<branch_id>[0-9]+)/(?P<customer_id>[0-9]+)/(?P<customer_group_id>[0-9]+)/$', views.GetAssetData.as_view(), name='get_asset_data'),    
    url(r'^listopenticketdependencyreport/$', views.ListOpenTicketDependencyReport.as_view(), name='list_open_ticket_dependency_report'),
    url(r'^listcallstatusassignedengineertrack/(?P<ticket_id>[0-9]+)/$', views.ListCallStatusAssignedEngineerTrack.as_view(), name='list_call_status_assigned_engineer_track'),
    url(r'^markallasread/$', views.MarkAllAsRead.as_view(), name='mark_all_asread'),
    url(r'^listqueue/$', views.ListQueue.as_view(), name='list_queue'),
    url(r'^createqueue/$', views.CreateQueue.as_view(), name='create_queue'),
    url(r'^updatequeue/(?P<pk>[0-9]+)/$', views.UpdateQueueDetails.as_view(), name='update_queue_details'),
    url(r'^createcallticketservicedesk/$', views.CreateCallTicketServiceDesk.as_view(), name='create_call_ticket_service_desk'),
    url(r'^actionpickup/(?P<pk>[0-9]+)/$', views.ActionPickUp.as_view(), name='action_pick_up'),
    url(r'^listcustomergroup/$', views.ListCustomerGroup.as_view(), name='list_customer_group'),
    url(r'^createcustomergroup/$', views.CreateCustomerGroup.as_view(), name='create_customer_group'),
    url(r'^updatecustomergroup/(?P<pk>[0-9]+)/$', views.UpdateCustomerGroupDetails.as_view(), name='update_customer_group_details'),
    url(r'^liststatustrackingreport/$', views.ListStatusTrackingReport.as_view(), name='list_status_tracking_report'),
    url(r'^displaystatustrackingreport/(?P<pk>[0-9]+)/$', views.DisplayStatusTrackingReportDetails.as_view(), name='display_status_tracking_report_details'),
	url(r'^listoperatingsystem/$', views.ListOperatingSystem.as_view(), name='list_operating_system'),
    url(r'^createoperatingsystem/$', views.CreateOperatingSystem.as_view(), name='create_operating_system'),
    url(r'^updateoperatingsystem/(?P<pk>[0-9]+)/$', views.UpdateOperatingSystemDetails.as_view(), name='update_operating_system_details'),
	url(r'^listram/$', views.ListRAM.as_view(), name='list_ram'),
    url(r'^createram/$', views.CreateRAM.as_view(), name='create_ram'),
    url(r'^updateram/(?P<pk>[0-9]+)/$', views.UpdateRAMDetails.as_view(), name='update_ram_details'),
	url(r'^listhardisktype/$', views.ListHardiskType.as_view(), name='list_hardisktype'),
    url(r'^createhardisktype/$', views.CreateHardiskType.as_view(), name='create_hardisktype'),
    url(r'^updatehardisktype/(?P<pk>[0-9]+)/$', views.UpdateHardiskTypeDetails.as_view(), name='update_hardisktype_details'),
    url(r'^listmemorycapacity/$', views.ListMemoryCapacity.as_view(), name='list_memory_capacity'),
    url(r'^creatememorycapacity/$', views.CreateMemoryCapacity.as_view(), name='create_memory_capacity'),
    url(r'^displaymemorycapacitydetails/(?P<pk>[0-9]+)/$', views.DisplayMemoryCapacityDetails.as_view(), name='display_memory_capacity_details'),
    url(r'^updatememorycapacity/(?P<pk>[0-9]+)/$', views.UpdateMemoryCapacityDetails.as_view(), name='update_memory_capacity_details'),
# HRMS url
    #url(r'listadminroles/$', views.ListAdminRoles.as_view(), name='list_admin_roles'),
    #url(r'createadminrole/$', views.CreateAdminRole.as_view(), name='create_admin_role'),
    #url(r'updateadminrole/(?P<pk>[0-9]+)/$', views.UpdateAdminRole.as_view(), name='update_admin_role'),
    url(r'listorganizationproject/$', views.ListOrganizationProject.as_view(), name='list_organization_project'),
    url(r'createorganizationproject/$', views.CreateOrganizationProject.as_view(), name='create_organization_project'),
    url(r'updateorganizationproject/(?P<pk>[0-9]+)/$', views.UpdateOrganizationProject.as_view(), name='update_organization_project'),
    #url(r'listregion/$', views.ListRegion.as_view(), name='list_region'),
    #url(r'createregion/$', views.CreateRegion.as_view(), name='create_region'),
    #url(r'updateregion/(?P<pk>[0-9]+)/$', views.UpdateRegion.as_view(), name='update_region'),
    url(r'listgrade/$', views.ListGrade.as_view(), name='list_grade'),
    url(r'creategrade/$', views.CreateGrade.as_view(), name='create_grade'),
    url(r'updategrade/(?P<pk>[0-9]+)/$', views.UpdateGrade.as_view(), name='update_grade'),
    url(r'listorganizationdepartment/$', views.ListOrganizationDepartment.as_view(), name='list_organization_department'),
    url(r'createorganizationdepartment/$', views.CreateOrganizationDepartment.as_view(), name='create_organization_department'),
    url(r'updateorganizationdepartment/(?P<pk>[0-9]+)/$', views.UpdateOrganizationDepartment.as_view(), name='update_organization_department'),
    url(r'listworklocation/$', views.ListWorkLocation.as_view(), name='list_worklocation'),
    url(r'createworklocation/$', views.CreateWorkLocation.as_view(), name='create_worklocation'),
    url(r'updateworklocation/(?P<pk>[0-9]+)/$', views.UpdateWorkLocation.as_view(), name='update_worklocation'),
    #url(r'listdateformat/$', views.ListDateFormat.as_view(), name='list_date_format'),
    #url(r'createdateformat/$', views.CreateDateFormat.as_view(), name='create_date_format'),
    #url(r'updatedateformatdetails/(?P<pk>[0-9]+)/$', views.UpdateDateFormatDetails.as_view(), name='update_date_format_details'),
    url(r'listorganization/$', views.ListOrganization.as_view(), name='list_organization'),
    url(r'createorganization/$', views.CreateOrganization.as_view(), name='create_organization'),
    url(r'updateorganizationdetails/(?P<pk>[0-9]+)/$', views.UpdateOrganizationDetails.as_view(), name='update_organization_details'),
    url(r'displayorganizationdetails/(?P<pk>[0-9]+)/$', views.DisplayOrganizationDetails.as_view(), name='display_organization_details'),
    url(r'listorganizationcontact/$', views.ListOrganizationContact.as_view(), name='list_organization_contact'),
    url(r'createorganizationcontact/(?P<organization_id>[0-9]+)/$', views.CreateOrganizationContact.as_view(), name='create_organization_contact'),
    url(r'updateorganizationcontactdetails/(?P<organization_id>[0-9]+)/(?P<pk>[0-9]+)/$', views.UpdateOrganizationContactDetails.as_view(), name='update_organization_contact_details'),
    url(r'liststatutorycomponents/$', views.ListStatutoryComponents.as_view(), name='list_statutory_components'),
    url(r'createorganizationesidetails/$', views.CreateOrganizationESIDetails.as_view(), name='create_organization_esi_details'),
    url(r'updateorganizationesidetails/(?P<pk>[0-9]+)/$', views.UpdateOrganizationESIDetails.as_view(), name='update_organization_esi_details'),
    url(r'listorganizationemployeepfdetails/$', views.ListOrganizationEmployeePFDetails.as_view(), name='list_organization_employee_pf_details'),
    url(r'createorganizationemployeepfdetails/$', views.CreateOrganizationEmployeePFDetails.as_view(), name='create_organization_employee_pf_details'),
    url(r'updateorganizationemployeepfdetails/(?P<pk>[0-9]+)/$', views.UpdateOrganizationEmployeePFDetails.as_view(), name='update_organization_employee_pf_details'),
    url(r'listorganizationtaxdetails/$', views.ListOrganizationTaxDetails.as_view(), name='list_organization_tax_details'),
    url(r'createorganizationtaxdetails/$', views.CreateOrganizationTaxDetails.as_view(), name='create_organization_tax_details'),
    url(r'updateorganizationtaxdetails/(?P<pk>[0-9]+)/$', views.UpdateOrganizationTaxDetails.as_view(), name='update_organization_tax_details'),
    url(r'listprofessionaltaxlocation/$', views.ListProfessionalTaxLocation.as_view(), name='list_professional_tax_location'),
    url(r'createprofessionaltaxlocation/$', views.CreateProfessionalTaxLocation.as_view(), name='create_professional_tax_location'),
    url(r'updateprofessionaltaxlocationdetails/(?P<pk>[0-9]+)/$', views.UpdateProfessionalTaxLocationDetails.as_view(), name='update_professional_tax_location_details'),
    url(r'listemployeebenefit/$', views.ListEmployeeBenefit.as_view(), name='list_employee_benefit'),
    url(r'createemployeebenefit/$', views.CreateEmployeeBenefit.as_view(), name='create_employee_benefit'),
    url(r'updateemployeebenefit/(?P<pk>[0-9]+)/$', views.UpdateEmployeeBenefit.as_view(), name='update_employee_benefit'),
    url(r'listprofessionaltaxslabs/$', views.ListProfessionalTaxSlabs.as_view(), name='list_professional_taxslabs'),
    url(r'createprofessionaltaxslabs/$', views.CreateProfessionalTaxSlabs.as_view(), name='create_professional_taxslabs'),
    url(r'updateprofessionaltaxslabs/(?P<pk>[0-9]+)/$', views.UpdateProfessionalTaxSlabs.as_view(), name='update_professional_taxslabs'),
    url(r'listpayschedule/$', views.ListPaySchedule.as_view(), name='list_Pay_schedule'),
    url(r'createpayschedule/$', views.CreatePaySchedule.as_view(), name='create_Pay_schedule'),
    url(r'updatepayscheduledetails/(?P<pk>[0-9]+)/$', views.UpdatePayScheduleDetails.as_view(), name='update_Pay_schedule_details'),
    url(r'listpreferences/$', views.ListPreferences.as_view(), name='list_preferences'),
    url(r'createpreferences/$', views.CreatePreferences.as_view(), name='create_preferences'),
    url(r'updatepreferencesdetails/(?P<pk>[0-9]+)/$', views.UpdatePreferencesDetails.as_view(), name='update_preferences_details'),
    url(r'listcountry/$', views.ListCountry.as_view(), name='list_country'),
    url(r'createcountry/$', views.CreateCountry.as_view(), name='create_country'),
    url(r'updatecountrydetails/(?P<pk>[0-9]+)/$', views.UpdateCountryDetails.as_view(), name='update_country_details'),
    url(r'liststate/$', views.ListState.as_view(), name='list_state'),
    url(r'createstate/$', views.CreateState.as_view(), name='create_state'),
    url(r'updatestatedetails/(?P<pk>[0-9]+)/$', views.UpdateStateDetails.as_view(), name='update_state_details'),
	url(r'listsalarycomponents/$', views.ListSalaryComponents.as_view(), name='list_salary_components'),
    url(r'createearning/$', views.CreateEarning.as_view(), name='create_earning'),
    url(r'updateearningdetails/(?P<pk>[0-9]+)/$', views.UpdateEarningDetails.as_view(), name='update_earning_details'),
    url(r'listdeduction/$', views.ListDeduction.as_view(), name='list_deduction'),
    url(r'creatededuction/$', views.CreateDeduction.as_view(), name='create_deduction'),
    url(r'updatedeductiondetails/(?P<pk>[0-9]+)/$', views.UpdateDeductionDetails.as_view(), name='update_deduction_details'),
	url(r'listsourceofhire/$', views.ListSourceOfHire.as_view(), name='list_source_of_hire'),
    url(r'createsourceofhire/$', views.CreateSourceOfHire.as_view(), name='create_source_of_hire'),
    url(r'updatesourceofhiredetails/(?P<pk>[0-9]+)/$', views.UpdateSourceOfHireDetails.as_view(), name='update_source_of_hire_details'),
	url(r'listrelationship/$', views.ListRelationship.as_view(), name='list_relationship'),
	url(r'createrelationship/$', views.CreateRelationship.as_view(), name='create_relationship'),
	url(r'updaterelationshipdetails/(?P<pk>[0-9]+)/$', views.UpdateRelationshipDetails.as_view(), name='update_relationship_details'),
	url(r'listrole/$', views.ListRole.as_view(), name='list_role'),
	url(r'createrole/$', views.CreateRole.as_view(), name='create_role'),
	url(r'updateroledetails/(?P<pk>[0-9]+)/$', views.UpdateRoleDetails.as_view(), name='update_role_details'),
	url(r'listbloodgroup/$', views.ListBloodGroup.as_view(), name='list_bloodgroup'),
	url(r'createbloodgroup/$', views.CreateBloodGroup.as_view(), name='create_bloodgroup'),
	url(r'updatebloodgroupdetails/(?P<pk>[0-9]+)/$', views.UpdateBloodGroupDetails.as_view(), name='update_bloodgroup_details'),
	url(r'listgender/$', views.ListGender.as_view(), name='list_gender'),
	url(r'creategender/$', views.CreateGender.as_view(), name='create_gender'),
	url(r'updategenderdetails/(?P<pk>[0-9]+)/$', views.UpdateGenderDetails.as_view(), name='update_gender_details'),
	url(r'listinvestmenttype/$', views.ListInvestmentType.as_view(), name='list_investment_type'),
	url(r'createinvestmenttype/$', views.CreateInvestmentType.as_view(), name='create_investment_type'),
	url(r'updateinvestmenttypedetails/(?P<pk>[0-9]+)/$', views.UpdateInvestmentTypeDetails.as_view(), name='update_investment_type_details'),
	url(r'listemployeestatus/$', views.ListEmployeeStatus.as_view(), name='list_employee_status'),
	url(r'createemployeestatus/$', views.CreateEmployeeStatus.as_view(), name='create_employee_status'),
	url(r'updateemployeestatusdetails/(?P<pk>[0-9]+)/$', views.UpdateEmployeeStatusDetails.as_view(), name='update_employee_status_details'),
	url(r'listemployeetype/$', views.ListEmployeeType.as_view(), name='list_employee_type'),
	url(r'createemployeetupe/$', views.CreateEmployeeType.as_view(), name='create_employee_type'),
	url(r'updateemployeetypedetails/(?P<pk>[0-9]+)/$', views.UpdateEmployeeTypeDetails.as_view(), name='update_employee_type_details'),
    url(r'listsalaryholdreleasereason/$', views.ListSalaryHoldReleaseReason.as_view(), name='list_salary_hold_release_reason'),
	url(r'createsalaryholdreleasereason/$', views.CreateSalaryHoldReleaseReason.as_view(), name='create_salary_hold_release_reason'),
    url(r'updatesalaryholdreleasereason/(?P<pk>[0-9]+)/$', views.UpdateSalaryHoldReleaseReason.as_view(), name='update_salary_hold_release_reason'),
    url(r'createsalarytemplate/$', views.CreateSalaryTemplate.as_view(), name='create_salary_template'),
    url(r'updatesalarytemplate/(?P<pk>[0-9]+)/$$', views.UpdateSalaryTemplate.as_view(), name='update_salary_template'),
    url(r'savesalarytemplate/$', views.SaveSalaryTemplate.as_view(), name='save_salary_template'),
    url(r'salarytemplate/$', views.SalaryTemplate.as_view(), name='salary_template'),
    url(r'^listemployeepersonalinfo/$', views.ListEmployeePersonalInfo.as_view(), name='list_employee_personal_info'),
    url(r'^createemployeepersonalinfo/$', views.CreateEmployeePersonalInfo.as_view(), name='create_employee_personal_info'),
    url(r'^updateemployeepersonalinfo/(?P<pk>[0-9]+)/$', views.UpdateEmployeePersonalInfo.as_view(), name='update_employee_personal_info'),
    url(r'^listemployeeworkinfo/$', views.ListEmployeeWorkInfo.as_view(), name='list_employee_work_info'),
    url(r'^createemployeeworkinfo/$', views.CreateEmployeeWorkInfo.as_view(), name='create_employee_work_info'),
    url(r'^updateemployeeworkinfo/(?P<pk>[0-9]+)/$', views.UpdateEmployeeWorkInfo.as_view(), name='update_employee_work_info'),
    url(r'^listemployeefile/$', views.ListEmployeeFile.as_view(), name='list_employee_file'),
    url(r'^createemployeefile/$', views.CreateEmployeeFile.as_view(), name='create_employee_file'),
    url(r'^updateemployeefile/(?P<pk>[0-9]+)/$', views.UpdateEmployeeFile.as_view(), name='update_employee_file'),
	url(r'listsummary/$', views.ListSummary.as_view(), name='list_summary'),
	url(r'createsummary/$', views.CreateSummary.as_view(), name='create_summary'),
	url(r'updatesummarydetails/(?P<pk>[0-9]+)/$', views.UpdateSummaryDetails.as_view(), name='update_summary_details'),
	url(r'listworkexperience/$', views.ListWorkExperience.as_view(), name='list_work_experience'),
	url(r'createworkexperience/$', views.CreateWorkExperience.as_view(), name='create_work_experience'),
	url(r'updateworkexperiencedetails/(?P<pk>[0-9]+)/$', views.UpdateWorkExperienceDetails.as_view(), name='update_work_experience_details'),
	url(r'listeducation/$', views.ListEducation.as_view(), name='list_education'),
	url(r'createeducation/$', views.CreateEducation.as_view(), name='create_education'),
	url(r'updateeducationdetails/(?P<pk>[0-9]+)/$', views.UpdateEducationDetails.as_view(), name='update_education_details'),
	url(r'listdependent/$', views.ListDependent.as_view(), name='list_dependent'),
	url(r'createdependent/$', views.CreateDependent.as_view(), name='create_dependent'),
	url(r'updatedependentdetails/(?P<pk>[0-9]+)/$', views.UpdateDependentDetails.as_view(), name='update_dependent_details'),
	url(r'listleavetype/$', views.ListLeaveType.as_view(), name='list_leave_type'),
	url(r'createleavetype/$', views.CreateLeaveType.as_view(), name='create_leave_type'),
	url(r'updateleavetypedetails/(?P<pk>[0-9]+)/$', views.UpdateLeaveTypeDetails.as_view(), name='update_leave_type_details'),
	url(r'listemployeeleaverequest/$', views.ListEmployeeLeaveRequest.as_view(), name='list_employee_leave_request'),
	url(r'createemployeeleaverequest/$', views.CreateEmployeeLeaveRequest.as_view(), name='create_employee_leave_request'),
	url(r'updateemployeeleaverequestdetails/(?P<pk>[0-9]+)/$', views.UpdateEmployeeLeaveRequestDetails.as_view(), name='update_employee_leave_request_details'),
    url(r'listemployee/$', views.ListEmployee.as_view(), name='list_employee'),
    url(r'createemployee/$', views.CreateEmployee.as_view(), name='create_employee'),
    url(r'updateemployee/(?P<pk>[0-9]+)/$', views.UpdateEmployee.as_view(), name='update_employee'),
]