USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[USR_Insert]    Script Date: 10.07.2026 16:15:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


ALTER    PROCEDURE [dbo].[USR_Insert] (@USR_Phone varchar(10) = '9041663063')
with recompile--, Encryption
AS 
 begin 
    set nocount on
	declare @USR_ID bigint = 0
	   --   , @USR_Password nvarchar(255) = ''
		  --, @USR_Email nvarchar(50) = ''
		  , @USR_Surname nvarchar(50)
		  , @USR_Name nvarchar(50)
		  , @USR_Patronymic nvarchar(50)
		  , @NRecClient bigint = 0

   BEGIN TRY 

        select  @USR_ID       = USR_ID
		   --   , @USR_Password = USR_Password
			  --, @USR_Email    = USR_Email
			  --, @USR_Surname  = USR_Surname 
			  --, @USR_Name     = USR_Name
			  --, @USR_Patronymic = USR_Patronymic
			  
		  from [dbo].[USR] (nolock) 
		  
		  where USR_Phone = @USR_Phone and USR_xDel = 0

       if @USR_ID != 0
	     begin
	      select @USR_ID       as USR_ID 
		    --   , @USR_Password as USR_Password
			   --, @USR_Email    as USR_Email 
			   --, @USR_Surname  as USR_Surname 
			   --, @USR_Name     as USR_Name
			   --, @USR_Patronymic as USR_Patronymic
		  return
		 end

        select top 1 
		        @NRecClient     = [NRecClient]
			  , @USR_Surname    = [Fam]
			  , @USR_Name       = [Name]
			  , @USR_Patronymic = [Patr]
			  
		  from [dbo].[aClient] (nolock) 
       where TelMob = @USR_Phone
	   order by DIzm desc

	   if @NRecClient != 0

		begin

		 insert into [dbo].[USR] (USR_Phone, USR_Surname, USR_Name, USR_Patronymic)
			 Values	 (@USR_Phone, concat(left(ltrim(@USR_Surname), 1), '.'), @USR_Name, @USR_Patronymic)

			set  @USR_ID = SCOPE_IDENTITY() 
			select @USR_ID as ID
		      --   , @USR_Password    as USR_Password
			     --, @USR_Email   	as USR_Email    	       

        end else
				select              -1 as ID
					   --, @USR_Password as USR_Password
			     --      , @USR_Email    as USR_Email                  
   END TRY


   BEGIN CATCH 

				select              -1 as ID
					   --, @USR_Password as USR_Password
			     --      , @USR_Email    as USR_Email  

   END CATCH

 end


 /*
 exec [dbo].[USR_Insert] '9920153035' 

 EXECUTE [dbo].[USR_Insert]    '9028718329'
 --*/
 --select * from [dbo].[aClient]
 --where TelMob = '9041663272'


    --     select  USR_ID
		  --    , USR_Password
			 -- , USR_Email
			  
		  --from [dbo].[USR] (nolock) 
		  
		  --where USR_Phone = '9028718329' and USR_xDel = 0

--select 1 from [dbo].[aClient] where TelMob = '9028718329'



USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[USR_Select]    Script Date: 10.07.2026 16:17:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


ALTER    PROCEDURE [dbo].[USR_Select] (@USR_ID bigint = 0)
with recompile--, Encryption
AS 
 begin 
    set nocount on
	declare @ID nvarchar(max)

   BEGIN TRY 

     if exists (select 1 from [dbo].[USR] (nolock)  where USR_ID = @USR_ID and USR_xDel = 0)
	  begin
	 	  set @ID = isnull((
		 select USR_Id as id
		      , USR_Id as _USR_Id
		      --, USR_Phone as phone
			  , USR_Email as email
			  , USR_Password as _USR_Password
			  --, USR_DReg
			  --, USR_xDel
			  , USR_Surname as surname
			  , USR_Name as [name]
			  , USR_Patronymic as patronymic
			  , USR_consent_to_mailing as consent_to_mailing
			  , case when USR_Password is null or len(ltrim(rtrim(isnull(USR_Password, '')))) < 1  THEN 1  ELSE 2  END AS _code

		 from USR 
				where USR_Id = @USR_ID 
				  and (USR_xDel is null or USR_xDel = 0)
			FOR JSON PATH, INCLUDE_NULL_VALUES )
          , '-1')

			  select  @ID  as ID 	

     end else 
		 select -1 as ID 
		  

             
   END TRY


   BEGIN CATCH 
        select  - 1 as ID      
		   --   , Null as USR_Password
			  --, Null as USR_Email

   END CATCH

 end


 /*
 exec [dbo].[USR_Select] 2

 EXECUTE [dbo].[USR_sI]    '9028718329'
 --*/



USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[USR_Update]    Script Date: 10.07.2026 16:17:51 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



ALTER     PROCEDURE [dbo].[USR_Update] (@USR_ID bigint = 0, @USR_Email varchar(50) = '', @USR_Password varchar(255) ='')
--with recompile--, Encryption
AS 
 begin 
    set nocount on
	--declare @p smallint = -1
	select @USR_Email = isnull(@USR_Email, ''), @USR_Password = isnull(@USR_Password, '')
   BEGIN TRY 

     if exists (select 1 from [dbo].[USR] (nolock)  where USR_ID = @USR_ID and USR_xDel = 0) 
	    --and (len(@USR_Email) > 0 or len(@USR_Password) > 0)
		--and len(@USR_Password) > 0
	   begin
	        
     --       if len(@USR_Email) > 0 or len(@USR_Password) > 0
			  --begin
				  update [dbo].[USR]
					set USR_Email    = @USR_Email --iif(len(@USR_Email)    > 0, @USR_Email,    USR_Email)
					  , USR_Password = iif(len(@USR_Password) > 0, @USR_Password, USR_Password)
					  , USR_consent_to_mailing = iif(len(@USR_Email) = 0, 0, USR_consent_to_mailing)
					where USR_ID = @USR_ID

               if len(@USR_Password) > 0 
			      begin
					  insert into [DLK].[dbo].[USR_Access] (USR_ID, [USR_Access_Value])
						  values
						  (@USR_ID, 1)
				  end


				--set   @p = 0
              --end  
			   select  @USR_ID as ID 


       end else 
				select  '-1'  as ID      
             
   END TRY


   BEGIN CATCH 
				select  '-1'  as ID      

   END CATCH

        --select  @p as USR_ID      


 end


 /*
 exec [dbo].[USR_SI] '9000000001' 

 EXECUTE [dbo].[USR_sI]    '9028718329'
 --*/
 --select * from [dbo].[aClient]
 --where TelMob = '9041663272'


    --     select  USR_ID
		  --    , USR_Password
			 -- , USR_Email
			  
		  --from [dbo].[USR] (nolock) 
		  
		  --where USR_Phone = '9028718329' and USR_xDel = 0

--select 1 from [dbo].[aClient] where TelMob = '9028718329'



USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[ZbTickets_Json]    Script Date: 10.07.2026 16:20:40 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





ALTER     PROCEDURE [dbo].[ZbTickets_Json] (@USR_Id varchar(10) = '9521449157', @Status NVARCHAR(20) = '')
  with recompile
AS 

 begin 
   set nocount on
   declare @ID nvarchar(max)
BEGIN TRY           

	set @ID = isnull(
	(select  z.Nomer as external_id
	      , z.[type]
	      , z.[StatZb] as [status]
	      , z.[ticket_status] as [ticket_status]
		  , a.[address]   as [address]
		  , z.[start_date]
		  , z.[end_date]
		  , convert(varchar, dateadd (dd, (select top 1 cast(ZN as int) FROM [spConstDin] (nolock) where  Dt <= [start_date]  order by Dt desc), [start_date]), 104) as [max_date]

		  , z.[benefits_end_date]
		  , z.[last_payment_date]
		  , z.[interest_rate_per_day]
		  , z.[interest_rate_per_year]
		  , z.[amount]
		  , z.[loan_debt]
		  , convert(nvarchar, z.[interest_debt]) as [interest_debt]
		  --, iif (exists (SELECT 1 FROM [DLK].[dbo].[DOC] where [DOC_xDel] = 0 and USR_Id = z.USR_Id)


			,( -- документ

			SELECT   [ID], [Name], [Link]  --isnull(
					  --(select [ID], [Name], [Link]
					   from
						 ( 
						 --не передаем простые документы, только ссылка на ЭЗБ
						 --SELECT [DOC_Id] as [ID]
							--	,convert(nvarchar(255), [DOC_NAME]) as [Name]
							--	,convert(nvarchar(255), [DOC_Link]) as [Link]
							--FROM [DLK].[dbo].[DOC] where [DOC_xDel] = 0 and USR_Id = z.USR_Id --FOR JSON PATH, INCLUDE_NULL_VALUES 

							-- union all 

							SELECT -1 as [ID]
								  ,convert(nvarchar(255), [DOC_NAME]) as [Name]
								  ,convert(nvarchar(255), [DOC_LINK]) as [Link]
								  --,''
							  FROM [DOCUM] d
							  where 
							  --
							  NrecZb = z.NRecZB
							  --[DOC_NAME] like '%5441304%'
							  and Doc_Vid = 'ЗБ'
							  and xDel = 0
						   )x FOR JSON PATH, INCLUDE_NULL_VALUES  
					   )

				--)

					as document 
		  ,
			(--предмет залога
				SELECT 
					  [name]
					, [status]
					--, [ocenka]
					--, [ocenkam]

					, (--характеристики
							SELECT 
								  [name]
								, [value]
							FROM [DLK].[dbo].[Item_characteristics] where yyy.item_id = item_id FOR JSON PATH, INCLUDE_NULL_VALUES 
					   )
			as characteristics
				FROM [DLK].[dbo].[Items] yyy where [ticket_id] = z.nreczb 
				
				FOR JSON PATH, INCLUDE_NULL_VALUES 
			) as items

--		  , 


    from [dbo].[ZbTickets] z
		left join [dbo].[spADR] a on z.nobj = a.nobj

	where z.USR_Id = @USR_Id
	   and (@Status = '' or @Status = [StatZb])
	   
	FOR JSON PATH, INCLUDE_NULL_VALUES ), '-1')


		select iif(ISJSON(@ID) = 1, @ID, '-1') as  ID 

END TRY 
BEGIN CATCH
		select '-1' as ID 
END CATCH


------[item_id] =    -63730042
--NRecZBPoz = -105951042 -- по позиции
        --order by NPoz 
--FOR JSON AUTO




 end
 /*
 exec [dbo].[ZbTickets_Json_dev] 42
 exec [dbo].[ZbTickets_Json] -63730042
  exec [dbo].[ZbTickets_Json] 5, 'archive'
 exec [dbo].[Items_json] null,-105951042
 */

--GO
-- exec [dbo].[DLK_TEL] '9221516383'

USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[Pay_created_at]    Script Date: 10.07.2026 16:22:51 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


ALTER  PROCEDURE [dbo].[Pay_created_at] (

	@PAY_date [nvarchar] (max) = 
	N'{

  "transaction_id": "333",
  "user_id": "2",
  "amount_due": 12.0,
  "payments": [
    {
      "ticket_id": "55555",
      "date": "12.12.2025",
      "amount": 12.0
    }
  ]
}'

)
AS 
 begin 
   set nocount on

        IF ISJSON(@PAY_date) = 0 
        BEGIN
            select '-1' as ID
            RETURN
        END

   BEGIN TRY
		drop table if exists #res
		drop table if exists #pay



		create table #res (transaction_id nvarchar(100), usr_id nvarchar(100), amount_due float, payments nvarchar(max))
		create table #pay (id int identity, transaction_id nvarchar(100), usr_id nvarchar(100), amount_due float, ticket_id nvarchar(100),[date] date, amount float)


	  insert into #res
		select  transaction_id, [user_id], amount_due, payments from 
				(
					SELECT [key], [value] FROM OPENJSON(@PAY_date)
				) as a
		pivot (max([value]) for [key] in (transaction_id, [user_id], amount_due, payments)) as upvt 


	  insert into #pay (transaction_id, usr_id, amount_due, ticket_id, [date], amount)
		select transaction_id
		      ,usr_id
			  ,amount_due
			  ,ticket_id
			  ,[date]
			  ,amount
			  from #res
				  CROSS APPLY OPENJSON(payments)
			  WITH("ticket_id" [nvarchar] (max), "date" date, "amount" float)


		--if (select count(*) from #pay) 
		-- != (select count(*) from #pay p
		--	 where   exists(select 1 from [dbo].[USR] where  [usr_id] = p.usr_id)
		--		  AND [date]   IS NOT NULL 
		--		  AND isnull([amount], 0)     > 0
		--		  AND isnull([amount_due], 0) > 0
		--	)

		--begin
  --          select '-1' as ID
  --          RETURN
		--end else
		--begin

		 insert into [DLK].[dbo].[PAY]
				 (
					   [USR_id]
					  ,[Nomer]
					  ,[PAY_date]
					  ,[PAY_amount]
					  ,[PAY_amount_due]
					  --,[PAY_created_at]
					  ,[PAY_transaction_id]
				 )

				select  usr_id
					  , ticket_id
					  , [date]
					  , amount
					  , iif(id = 1, amount_due, null)
					  , transaction_id

				from #pay

			 select '0' as ID
		   --end
		    --  ,[USR_id]
      --,[NrecZb]
      --,[PAY_date]
      --,[PAY_amount]
      --,[PAY_amount_due]
      --,[PAY_created_at]
      --,[PAY_transaction_id]


   END TRY
   BEGIN CATCH
	 select '-1' as ID
   END CATCH



 end
-- go
-- exec [dbo].[Pay_created_at] 
-- '{
--  "transaction_id": "23d93cac-000f-5000-8000-126628f15141",
--  "user_id": "2",
--  "amount_due": 198.00,
--  "payments": [
--    {
--      "ticket_id": "45d93cac-000f-5000-8000-133328f15141",
--      "date": "13.07.2025",
--      "amount": 100.00
--    },
--    {
--      "ticket_id": "123123-000f-5000-8000-133328f15141",
--      "date": "13.12.2025",
--      "amount": 10.00
--    }
--  ]
--}'

--GO
-- exec [dbo].[Pay_created_at_dev] '{
--  "transaction_id": "23d93cac-000f-5000-8000-126628f15141",
--  "user_id": "2",
--  "amount_due": 198.00,
--  "payments": [
--    {
--      "ticket_id": "45d93cac-000f-5000-8000-133328f15141",
--      "date": "13.07.2025",
--      "amount": 100.00
--    },
--    {
--      "ticket_id": "123123-000f-5000-8000-133328f15141",
--      "date": "13.12.2025",
--      "amount": 10.00
--    }
--  ]
--}'

USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[Doc_Update_signed]    Script Date: 10.07.2026 16:23:26 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


ALTER   PROCEDURE [dbo].[Doc_Update_signed] (
--usr_id, Doc_type, Doc_name, Doc_link, Doc_desc, Doc_date

	@DOC_Id [bigint] = 0,
	@DOC_Is_signed  int = 0
	-- подписан

)
AS 
 begin 
   set nocount on
   --declare @Doc_signed_at datetime

   BEGIN TRY
   DECLARE @ID TABLE (ID bigint);

      update [DLK].[dbo].[DOC]
	    set DOC_Is_signed  = @DOC_Is_signed, Doc_signed_at = getdate()
		OUTPUT INSERTED.DOC_Id
		INTO @ID
	  where @DOC_Id = DOC_Id

	 select top 1 ID from @ID

   END TRY
   BEGIN CATCH
	 select -1 as ID
   END CATCH

 end

USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[DOC_Select_ID]    Script Date: 10.07.2026 16:23:49 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



ALTER    PROCEDURE [dbo].[DOC_Select_ID] (@USR_ID bigint = 0)
with recompile--, Encryption
AS 
 begin 
    set nocount on
	declare @ID nvarchar(max)

   BEGIN TRY 


		  begin
		  set @ID = isnull((
			SELECT [DOC_Id]   as id
				  ,[DOC_Type] as [type]
				  ,[DOC_Name] as [name]
				  ,convert(varchar, [DOC_Date], 104) as [date]
				  ,[DOC_Link] as [link]
				  --,[DOC_Pass]
				  ,[DOC_Desc] as [desc]
				  ,[DOC_Is_signed] as [is_signed]
				  --,[DOC_Signed_at]
				  --,[USR_Id]
				  --,[DOC_Created_at]
				  --,[DOC_xDel]
			  FROM [DLK].[dbo].[DOC]
			  where USR_Id = @USR_ID
				  and DOC_Type != 'user'
				  and DOC_xDel = 0
			  order by [DOC_Type], [DOC_Id] desc
			  FOR JSON PATH, INCLUDE_NULL_VALUES) 
			, '-1')

        select  @ID  as ID    
end
             
   END TRY


   BEGIN CATCH 
        select  '-1'  as ID      


   END CATCH

 end
 --go
 --exec [dbo].[DOC_Select_ID] 2

USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[USR_Update_consent_to_mailing]    Script Date: 10.07.2026 16:24:11 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



ALTER       PROCEDURE [dbo].[USR_Update_consent_to_mailing] (@USR_ID bigint = 0, @USR_consent_to_mailing bit)
with recompile--, Encryption
AS 
 begin 
    set nocount on
	--declare @p smallint = -1

   BEGIN TRY 
     if exists (select 1 from [dbo].[USR] (nolock)  where USR_ID = @USR_ID and USR_xDel = 0) 

	   begin
	        
				  update [dbo].[USR]
					set USR_consent_to_mailing    = @USR_consent_to_mailing

					where USR_ID = @USR_ID

				select  @USR_ID  as ID      
       end else
	   			select  '- 1'  as ID 

 
   END TRY


   BEGIN CATCH 
				select  '- 1'  as ID      

   END CATCH


 end


USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[USR_Access_Select]    Script Date: 10.07.2026 16:24:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



ALTER    PROCEDURE [dbo].[USR_Access_Select] (@USR_ID bigint, @min integer = 15)
with recompile--, Encryption
AS 
 begin 
    set nocount on

	declare  @dt datetime = getdate()
		   --, @k  integer = 4

   BEGIN TRY 

		SELECT 
			 [USR_Access_Date]
			,[USR_Access_Value]
			--,dateadd(mi, - @min, @dt)
          into #res
 		FROM [DLK].[dbo].[USR_Access] (nolock)
		where USR_ID = @USR_ID 
		  and USR_Access_Date > dateadd(mi, - @min, @dt)
      --if (
          select count(*) as ID  from #res   
		   where [USR_Access_Date] > isnull((select max([USR_Access_Date]) from #res where [USR_Access_Value] = 1), dateadd(mi, - @min, @dt))
		    and [USR_Access_Value] = 0
			--) > @k 

         --select '-1' as ID     
     -- else 
     --     select count(*) as ID  from #res   
		   --where [USR_Access_Date] > isnull((select max([USR_Access_Date]) from #res where [USR_Access_Value] = 1), dateadd(mi, - @min, @dt))
		   -- and [USR_Access_Value] = 0
		 
   END TRY


   BEGIN CATCH 
        select  '-1'  as ID      


   END CATCH

 end
 --go 
 --exec [dbo].[USR_Access_Select] 1, 6



USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[usp_CalculatePaymentDistribution]    Script Date: 10.07.2026 16:25:21 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



ALTER       PROCEDURE [dbo].[usp_CalculatePaymentDistribution] (@Json nvarchar(4000))
AS 
 begin 
   set nocount on

	 if ISJSON (@Json) = 0
	   begin 
		  select '-1' ID 
	   return
	 end


    begin try

		drop table if exists #r
		create table #r (ticket_id varchar(7), amount decimal(20,2), sProc decimal(20,2), percent_amount decimal(20,2)) 

		insert into #r 
		(ticket_id, amount, sProc)

			SELECT ticket_id
				 , amount
				 --, [dCBDL].[dbo].[_Get_Din_Procent_202308] (ticket_id, null, getdate(), 2) as sProc
				 , [dCBDL].[dbo].[_Get_Din_Procent_Lk] (ticket_id, null, getdate(), 2) as sProc
			FROM OpenJson(@Json)

			WITH(   
						   ticket_id   VARCHAR(7)   '$.ticket_id'
						  ,amount decimal(20,2) '$.amount'
				)

 --select * from #r
 --return

 declare @ticket_id varchar(7)
		 , @amount decimal(20,2) = 0
		 , @sProc  decimal(20,2) = 0
		 , @PaymentAmount decimal(20,2) = 0
		 , @ID nvarchar(max)
		 , @NRecZBPoz bigint
		 , @Opay decimal(20,2) = 0
		 , @pay decimal(20,2) = 0


create table #pay (ticket_id varchar(7), pay decimal(20,2), paym decimal(20,2), [name] nvarchar(255), NRecZBPoz bigint, OstkredP decimal(20,2))

     DECLARE my_cur CURSOR FOR  
	    select  ticket_id
		      , amount 
			  , sProc
		from #r 
      
        OPEN my_cur
   --считываем данные первой строки в наши переменные
   FETCH NEXT FROM my_cur 
   INTO @ticket_id, @amount, @sProc

   --если данные в курсоре есть, то заходим в цикл
   --и крутимся там до тех пор, пока не закончатся строки в курсоре
   WHILE @@FETCH_STATUS = 0
   BEGIN
       --select @ticket_id, @amount, @sProc

	   if @sProc >= @amount
	     begin
		   update #r 
		     set percent_amount = @amount
			 where ticket_id = @ticket_id

		 end 
		 else
		  begin 
		  		   update #r 
					 set percent_amount = sProc
					 where ticket_id = @ticket_id

				set @PaymentAmount = round(@amount - @sProc, 2)

				insert into #pay
				select Nomer
					, round(@PaymentAmount / Ostkred * OstkredP, 2) pay
					, sum(round(@PaymentAmount / Ostkred * OstkredP, 2)) over () paym
					--, sum(round(@PaymentAmount / Ostkred * OstkredP, 2)) over (order by OstkredP desc, NRecZBPoz) paymm
					, concat(NmKlass, ' (', NmMat, ' ', proba, ', ', OcenPrs, '*', vesM, ' г) ') as [name]
					--,null
					, NRecZBPoz
					, OstkredP
					--, Ostkred
					--, OstkredP
					--, @PaymentAmount Payment
					--,@PaymentAmount / Ostkred * OstkredP
				from [dbo].zZBPoz z
				where @ticket_id = Nomer


		select @Opay = sum(PAY) 
		  from #pay 
		  where @ticket_id = ticket_id
--select * from #pay

WHILE @PaymentAmount != @Opay
 begin

			DECLARE my_pay CURSOR FOR  
				select NRecZBPoz from #pay
					order by OstkredP desc, NRecZBPoz 
			OPEN my_pay 
			--считываем данные первой строки в наши переменные
			FETCH NEXT FROM my_pay 

			INTO @NRecZBPoz--, @Opay
			--если данные в курсоре есть, то заходим в цикл
			--и крутимся там до тех пор, пока не закончатся строки в курсоре
			WHILE @@FETCH_STATUS = 0
			BEGIN
			  if @PaymentAmount - @Opay > 0

				update #pay
					set pay = pay + 0.01, @Opay = @Opay + 0.01
						where NRecZBPoz = @NRecZBPoz and @ticket_id = ticket_id
              else 
				update #pay
					set pay = pay - 0.01, @Opay = @Opay - 0.01
						where NRecZBPoz = @NRecZBPoz and @ticket_id = ticket_id

            if @PaymentAmount = @Opay
			   break

		    FETCH NEXT FROM my_pay
			INTO @NRecZBPoz
			--, @Opay

		  END
		  --select @PaymentAmount - @Opay
--select sum(pay), @PaymentAmount,@amount, @sProc  from #pay
	   --закрываем курсор
	   CLOSE my_pay
	   DEALLOCATE my_pay

		   end
end
	   FETCH NEXT FROM my_cur 
       INTO @ticket_id, @amount, @sProc

      END
	  --select * from #pay
   --закрываем курсор
   CLOSE my_cur
   DEALLOCATE my_cur

	set @ID = isnull(
	   (select  ticket_id
			, round(cast(percent_amount as decimal(20, 2)), 2) as percent_amount
			, (select -- NmKlass
					 [name]
				   , round(cast(pay as decimal(20, 2)), 2) as [payment_amount]
				 from #pay where r.ticket_id = ticket_id and pay != 0 FOR JSON PATH, INCLUDE_NULL_VALUES) as [items]	 
		 
		 from #r r
	  FOR JSON PATH, INCLUDE_NULL_VALUES 
	  ), -1)

		select iif(ISJSON(@ID) = 1, @ID, '-1') as  ID 



  insert into [DLK].[dbo].[CHK] ([Nomer], [percent_amount], [NAME], [payment_amount],[CHK_created_at])
		select  r.ticket_id
			, round(cast(r.percent_amount as decimal(20, 2)), 2) as percent_amount
			, isnull([name], '') as [name]
			, isnull(round(cast(p.pay as decimal(20, 2)), 2), 0) as [payment_amount]
			, getdate()
		 from #r r
		  left join #pay p on r.ticket_id = p.ticket_id and p.pay != 0 

    end try
	begin catch
	  select '-1' ID 
	end   catch 

 --select * from [dbo].[ZbTickets]
 --  where NRecZB= -8964084

 end

--go
-- exec [dbo].[usp_CalculatePaymentDistribution_dev] 
-- '[
--  {
--    "ticket_id": "5551094",
--    "amount": 10000
--  }
--]'


USE [DLK]
GO
/****** Object:  StoredProcedure [dbo].[USR_Insert]    Script Date: 10.07.2026 16:25:41 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


