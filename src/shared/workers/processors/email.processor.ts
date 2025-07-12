import { Processor } from '@nestjs/bullmq'
import { Logger } from '@nestjs/common'
import { Job } from 'bullmq'

import { APP_BULL_QUEUES } from 'src/shared/enums/app.enum'
import { AWS_SES_EMAIL_TEMPLATES } from 'src/shared/aws/enums/aws.ses.enum'
import { ISendEmailBasePayload, IWelcomeEmailDataPaylaod } from 'src/shared/helper/interfaces/email.interface'
import { HelperEmailService } from 'src/shared/helper/services/helper.email.service'

@Processor(APP_BULL_QUEUES.EMAIL)
export class EmailProcessorWorker {
	private logger = new Logger(EmailProcessorWorker.name)

	constructor(private readonly helperEmailService: HelperEmailService) {}

	async [AWS_SES_EMAIL_TEMPLATES.WELCOME_EMAIL](
		job: Job<ISendEmailBasePayload<IWelcomeEmailDataPaylaod>, any, string>
	) {
		const { toEmails, data } = job.data

		await this.helperEmailService.sendEmail({
			emails: toEmails,
			emailType: AWS_SES_EMAIL_TEMPLATES.WELCOME_EMAIL,
			payload: data
		})

		this.logger.log('Email sent successfully')
	}
}
