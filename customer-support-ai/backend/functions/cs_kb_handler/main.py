import boto3
import json
import logging
import os
import traceback
from datetime import datetime
from security_utils import SecurityValidator, InputSanitizer, SecurityHeaders
from bedrock_monitor import get_bedrock_monitor
from user_analytics import get_user_analytics
from result_filter import get_result_filter, get_result_validator
from access_control import get_access_control, get_privacy_detector

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize security validator
security_validator = SecurityValidator()

DEFAULT_MODEL_ID = "amazon.nova-lite-v1:0"
DEFAULT_AWS_REGION = "us-east-1"
external_source_id = os.environ['EXTERNAL_SOURCE_ID']
knowledge_base_id = os.environ['KNOWLEDGE_BASE_ID']

aws_region = os.environ.get('AWS_REGION', DEFAULT_AWS_REGION)
model_id = os.environ.get('MODEL_ID', DEFAULT_MODEL_ID)
guardrail_enabled = os.environ.get('GUARDRAIL_ENABLED', 'true').lower() == 'true'

internal_source_id = os.environ.get('INTERNAL_SOURCE_ID', '')

# Initialize Bedrock clients
bedrock_agent = boto3.client('bedrock-agent-runtime', region_name=aws_region)
bedrock = boto3.client('bedrock-runtime', region_name=aws_region)


def create_prompt(query_text, context):
    """
    Creates a formatted prompt with query and context for LLM
    """
    return f"""Based on the following context, please answer the question: {query_text}

Context:
{context}

Please provide a clear and concise answer based only on the information provided in the context."""


def create_guardrail():
    """
    Creates and returns a guardrail configuration
    """
    return {
        "contentPolicyConfig": {
            "filters": {
                "hate": "HIGH",
                "insults": "HIGH",
                "sexual": "HIGH",
                "violence": "HIGH",
                "misconduct": "HIGH",
                "promptAttack": "HIGH"
            }
        },
        "sensitiveInformationPolicyConfig": {
            "sensitiveInformationTypes": {
                "PERSON_NAME": "REDACT",
                "EMAIL": "REDACT",
                "PHONE_NUMBER": "REDACT",
                "CREDIT_DEBIT_NUMBER": "REDACT",
                "BANK_ROUTING_NUMBER": "REDACT",
                "ADDRESS": "REDACT",
                "SSN": "REDACT",
                "DATE_OF_BIRTH": "REDACT"
            }
        }
    }


def apply_bedrock_guardrail(text):
    """
    Apply Bedrock guardrails using the ApplyGuardrail API
    """
    if not guardrail_enabled or not text:
        return text
    
    try:
        # Use Bedrock's ApplyGuardrail API if guardrail is configured
        guardrail_id = os.environ.get('GUARDRAIL_ID')
        guardrail_version = os.environ.get('GUARDRAIL_VERSION', 'DRAFT')
        
        if guardrail_id:
            logger.info(f"processing the response through guardrail {guardrail_id}")
            response = bedrock.apply_guardrail(
                guardrailIdentifier=guardrail_id,
                guardrailVersion=guardrail_version,
                source='OUTPUT',
                content=[
                    {
                        'text': {
                            'text': text
                        }
                    }
                ]
            )
            
            # Log the full response for debugging
            logger.info(f"Guardrail response: {json.dumps(response, default=str)}")
            
            if response.get('action') == 'BLOCKED':
                logger.warning("Content blocked by Bedrock guardrail")
                return "I apologize, but I cannot provide that information due to content restrictions."
            
            # Return the potentially modified text
            outputs = response.get('outputs', [])
            if outputs and outputs[0].get('text'):
                logger.info("Content passed guardrail checks")
                return outputs[0]['text']['text']
            
            # Guardrail processed but no output - return original
            logger.info("Content passed guardrail checks (no modifications)")
            return text
        
        # No guardrail ID configured - return text as-is
        logger.info("No guardrail ID configured, skipping guardrail validation")
        return text
        
    except Exception as e:
        logger.warning(f"Guardrail API failed: {e}")
        return text





def invoke_llm(prompt):
    """
    Invoke LLM Model with the given prompt
    """
    generated_text = ''  
    try:

        # Create body as a dictionary first
        request_body = {}
        
        print(f"Processing request with {model_id} LLM.")

        # Add the switch case to create request body based on the model_id
        if "amazon.nova" in model_id:

            # Define your system prompt(s).
            system_list = [
                        {
                            "text": prompt
                        }
            ]

            # Define one or more messages using the "user" and "assistant" roles.
            message_list = [{"role": "user", "content": [{"text": prompt}]}]

            # Configure the inference parameters.
            inf_params = {"maxTokens": 500, "topP": 0.9, "topK": 20, "temperature": 0.7}

            request_body = {
                "schemaVersion": "messages-v1",
                "messages": message_list,
                "system": system_list,
                "inferenceConfig": inf_params,
            }
            # Convert dictionary to JSON string
            body = json.dumps(request_body)
            
            print(f"LLM Request : {body}")

            # Invoke the model with the response stream
            response = bedrock.invoke_model_with_response_stream(
                modelId=model_id, body=body
            )

            if response:
                logger.info("Successfully received response from LLM %s", response)

                if response.get('blocked'):
                    logger.warning("Content was blocked by guardrails")
                    return "I apologize, but I cannot provide that information due to content restrictions."

                request_id = response.get("ResponseMetadata").get("RequestId")
                print(f"Request ID: {request_id}")
                print("Awaiting first token...")

                chunk_count = 0
                time_to_first_token = None


                # Process the response stream
                stream = response.get("body")
                start_time = datetime.now()
                if stream:
                    for event in stream:
                        chunk = event.get("chunk")
                        if chunk:
                            # Print the response chunk
                            chunk_json = json.loads(chunk.get("bytes").decode())
                            # Pretty print JSON
                            # print(json.dumps(chunk_json, indent=2, ensure_ascii=False))
                            content_block_delta = chunk_json.get("contentBlockDelta")
                            if content_block_delta:
                                if time_to_first_token is None:
                                    time_to_first_token = datetime.now() - start_time
                                    print(f"Time to first token: {time_to_first_token}")

                                chunk_count += 1
                                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f")
                                print(f"{current_time} - ", end="")
                                print(content_block_delta.get("delta").get("text"), end="")
                                generated_text += content_block_delta.get("delta").get("text")
                    print(f"Total chunks: {chunk_count}")
                    
                    # Apply guardrails for streaming responses
                    if guardrail_enabled:
                        logger.info("Applying Bedrock guardrails to response")
                        generated_text = apply_bedrock_guardrail(generated_text)
                    
            else:   
                logger.error("Failed to receive response from LLM")

        elif "anthropic.claude" in model_id:
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 1000,
                "temperature": 0.5
            }

            # Convert dictionary to JSON string
            body = json.dumps(request_body)
            logger.info("Invoking LLM model %s for %s", model_id, body)
            response = bedrock.invoke_model(
                modelId=model_id,
                contentType="application/json",
                accept="application/json",
                body=body
            )
            if response:
                logger.info("Successfully received response from LLM %s", response)

                if response.get('blocked'):
                    logger.warning("Content was blocked by guardrails")
                    return "I apologize, but I cannot provide that information due to content restrictions."

                response_body = json.loads(response.get('body').read())
                generated_text = response_body['content'][0]['text']
                
                # Apply guardrails for non-streaming responses
                if guardrail_enabled:
                    generated_text = apply_bedrock_guardrail(generated_text)
            else:
                logger.error("Failed to receive response from LLM")

        else:
            raise ValueError(f"Unsupported model_id: {model_id}")
        
        return generated_text

    except Exception as e:
        logger.warning("Error invoking LLM - Full details: %s", str(e))
        logger.warning("Error type: %s", type(e))
        logger.warning("Stacktrace: %s", traceback.format_exc())
        raise


def get_rag_response(query_text, source_ids=[]):
    """
    Get response from RAG using Bedrock Agent
    """
    print(f"knowledge_base_id: {knowledge_base_id} - {query_text}")

    retrieve_params = {
        "knowledgeBaseId": knowledge_base_id,
        "retrievalQuery": {
            "text": query_text
        },
        "retrievalConfiguration": {
            "vectorSearchConfiguration": {
                "numberOfResults": 3
            }
        }
    }

    # Add filter based on the number of source_ids
    if len(source_ids) == 1:
        # Single datasource filter
        retrieve_params["retrievalConfiguration"]["vectorSearchConfiguration"]["filter"] = {
            "equals": {
                "key": "x-amz-bedrock-kb-data-source-id",
                "value": source_ids[0]
            }
        }
        logger.info("Using single datasource filter: %s", source_ids[0])
    elif len(source_ids) > 1:
        # Create a dynamic OR filter with all source_ids
        or_conditions = []
        for source_id in source_ids:
            or_conditions.append({
                "equals": {
                    "key": "x-amz-bedrock-kb-data-source-id",
                    "value": source_id
                }
            })
        
        retrieve_params["retrievalConfiguration"]["vectorSearchConfiguration"]["filter"] = {
            "orAll": or_conditions
        }
        logger.info("Using OR filter for multiple datasources: %s", source_ids)
        
        
    logger.info("Retrieving RAG response for source_ids:  %s", source_ids)
    logger.info("Retrieval parameters: %s ", retrieve_params)

    response = bedrock_agent.retrieve(**retrieve_params)
    print(f"response: {response}")
                
    return response


def cs_kb_handler(event, context):
    """
    Main Lambda handler function with enhanced security
    """
    try:
        # Get request context for security logging
        request_id = context.aws_request_id if context else 'unknown'
        
        # Handle both API Gateway and direct Lambda invocation contexts
        if 'requestContext' in event:
            # API Gateway invocation
            source_ip = event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
            user_agent = event.get('headers', {}).get('User-Agent', 'unknown')
        else:
            # Direct Lambda invocation from Streamlit
            request_context = event.get('request_context', {})
            source_ip = 'streamlit_app'  # Streamlit app doesn't have direct IP access
            user_agent = request_context.get('user_agent', 'Streamlit-Frontend')
        
        # Get user information from payload
        user_id = event.get('user_id', 'anonymous')
        session_token = event.get('session_token', '')
        
        logger.info("Received event: %s", json.dumps({
            'request_id': request_id,
            'source_ip': source_ip,
            'user_agent': user_agent,
            'has_query': 'query_text' in event,
            'has_user_type': 'user_type' in event
        }))

        # Extract and sanitize input parameters
        raw_query_text = event.get('query_text', 'What are the recalled brand names')
        raw_user_type = event.get('user_type', '').lower()
        
        # Sanitize inputs
        query_text = InputSanitizer.sanitize_query(raw_query_text)
        user_type = InputSanitizer.sanitize_user_type(raw_user_type)
        
        # Security validation
        is_valid, validation_message = security_validator.validate_input(query_text, user_type)
        if not is_valid:
            security_validator.log_security_event(
                'INPUT_VALIDATION_FAILED',
                {
                    'request_id': request_id,
                    'source_ip': source_ip,
                    'user_type': user_type,
                    'validation_error': validation_message,
                    'query_length': len(raw_query_text)
                },
                'HIGH'
            )
            return {
                'statusCode': 400,
                'headers': SecurityHeaders.get_security_headers(),
                'body': json.dumps({
                    'error': 'Invalid input',
                    'message': validation_message
                })
            }
        
        # Rate limiting check using authenticated user_id
        rate_limit_ok, rate_limit_message = security_validator.check_rate_limit(user_id, source_ip)
        if not rate_limit_ok:
            security_validator.log_security_event(
                'RATE_LIMIT_EXCEEDED',
                {
                    'request_id': request_id,
                    'source_ip': source_ip,
                    'user_type': user_type,
                    'user_id': user_id
                },
                'MEDIUM'
            )
            return {
                'statusCode': 429,
                'headers': SecurityHeaders.get_security_headers(),
                'body': json.dumps({
                    'error': 'Rate limit exceeded',
                    'message': rate_limit_message
                })
            }
        
        # Bedrock query pattern analysis
        try:
            bedrock_monitor = get_bedrock_monitor()
            query_allowed, bedrock_reason, bedrock_metrics = bedrock_monitor.analyze_query_pattern(
                user_id, query_text, source_ip
            )
            
            if not query_allowed:
                security_validator.log_security_event(
                    'BEDROCK_QUERY_BLOCKED',
                    {
                        'request_id': request_id,
                        'source_ip': source_ip,
                        'user_type': user_type,
                        'user_id': user_id,
                        'reason': bedrock_reason,
                        'metrics': bedrock_metrics
                    },
                    'HIGH'
                )
                return {
                    'statusCode': 403,
                    'headers': SecurityHeaders.get_security_headers(),
                    'body': json.dumps({
                        'error': 'Query blocked',
                        'message': 'Query pattern analysis detected suspicious activity'
                    })
                }
            
            logger.info(f"Bedrock query analysis passed: {bedrock_reason}")
            
        except Exception as e:
            logger.warning(f"Bedrock monitoring failed: {e}")
            # Continue processing - don't block on monitoring failure
        
        # User behavior analytics
        try:
            user_analytics = get_user_analytics()
            behavior_ok, behavior_reason, behavior_data = user_analytics.analyze_user_behavior(
                user_id, query_text, source_ip, user_agent, session_token
            )
            
            if not behavior_ok:
                security_validator.log_security_event(
                    'USER_BEHAVIOR_ANOMALY',
                    {
                        'request_id': request_id,
                        'source_ip': source_ip,
                        'user_type': user_type,
                        'user_id': user_id,
                        'reason': behavior_reason,
                        'behavior_data': behavior_data
                    },
                    'HIGH'
                )
                return {
                    'statusCode': 429,
                    'headers': SecurityHeaders.get_security_headers(),
                    'body': json.dumps({
                        'error': 'Behavior analysis failed',
                        'message': 'Unusual usage pattern detected'
                    })
                }
            
            logger.info(f"User behavior analysis passed: {behavior_reason}")
            
        except Exception as e:
            logger.warning(f"User behavior analytics failed: {e}")
            # Continue processing - don't block on analytics failure
        
        logger.info("Processing request for user_type: %s", user_type)

        if user_type == 'external' or user_type == 'internal':
            logger.info("Valid user type provided: %s", user_type) 
            if user_type == 'external':
                source_ids = [external_source_id]
            else:
                # For internal users, we need to specify internal_source_id
                source_ids = [internal_source_id,external_source_id]
        else:
            logger.warning("Invalid user type provided: %s", user_type)
            security_validator.log_security_event(
                'INVALID_USER_TYPE',
                {
                    'request_id': request_id,
                    'source_ip': source_ip,
                    'provided_user_type': user_type,
                    'raw_user_type': raw_user_type
                },
                'HIGH'
            )
            raise ValueError("Invalid user type. Must be 'internal' or 'external'")
        
        # Multi-layer access control validation
        try:
            access_control = get_access_control()
            access_allowed, access_reason, access_metadata = access_control.validate_access_request(
                user_id, user_type, query_text, source_ids
            )
            
            if not access_allowed:
                security_validator.log_security_event(
                    'ACCESS_CONTROL_VIOLATION',
                    {
                        'request_id': request_id,
                        'source_ip': source_ip,
                        'user_type': user_type,
                        'user_id': user_id,
                        'reason': access_reason,
                        'access_metadata': access_metadata
                    },
                    'HIGH'
                )
                return {
                    'statusCode': 403,
                    'headers': SecurityHeaders.get_security_headers(),
                    'body': json.dumps({
                        'error': 'Access denied',
                        'message': 'Multi-layer access control validation failed'
                    })
                }
            
            logger.info(f"Access control validation passed: {access_reason}")
            
        except Exception as e:
            logger.warning(f"Access control validation failed: {e}")
            # Continue processing - don't block on access control failure

        # Get RAG response
        logger.info("Requesting RAG response")
        response = get_rag_response(query_text, source_ids)
        results = response.get('retrievalResults', [])

        if not results:
            logger.info("No results found in RAG response")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No relevant data found.'})
            }
        
        # Privacy violation detection
        try:
            privacy_detector = get_privacy_detector()
            violation_detected, violation_type, violation_data = privacy_detector.detect_privacy_violation(
                user_id, query_text, results, user_type
            )
            
            if violation_detected:
                security_validator.log_security_event(
                    'PRIVACY_VIOLATION_DETECTED',
                    {
                        'request_id': request_id,
                        'source_ip': source_ip,
                        'user_type': user_type,
                        'user_id': user_id,
                        'violation_type': violation_type,
                        'violation_data': violation_data
                    },
                    'CRITICAL'
                )
                return {
                    'statusCode': 403,
                    'headers': SecurityHeaders.get_security_headers(),
                    'body': json.dumps({
                        'error': 'Privacy violation detected',
                        'message': 'Query or results contain privacy-sensitive information'
                    })
                }
            
            logger.info(f"Privacy violation check passed: {violation_type}")
            
        except Exception as e:
            logger.warning(f"Privacy violation detection failed: {e}")
            # Continue processing - don't block on privacy detection failure

        # Extract context and prepare prompt
        context = results[0].get('content', {}).get('text', '')
        prompt = create_prompt(query_text, context)
        logger.info("Created prompt with context")

        # Get response from LLM
        logger.info("Requesting LLM for generating response")
        llm_response = invoke_llm(prompt)
        logger.info("Received LLM response")
        
        # Apply result filtering and validation (secondary security layer)
        try:
            # Validate result quality and security
            result_validator = get_result_validator()
            is_valid, validation_reason, validation_data = result_validator.validate_result(
                llm_response, context, user_type
            )
            
            if not is_valid:
                security_validator.log_security_event(
                    'RESULT_VALIDATION_FAILED',
                    {
                        'request_id': request_id,
                        'user_id': user_id,
                        'user_type': user_type,
                        'reason': validation_reason,
                        'validation_data': validation_data
                    },
                    'MEDIUM'
                )
                return {
                    'statusCode': 422,
                    'headers': SecurityHeaders.get_security_headers(),
                    'body': json.dumps({
                        'error': 'Result validation failed',
                        'message': 'Generated response did not meet security requirements'
                    })
                }
            
            # Filter result for sensitive content
            result_filter = get_result_filter()
            filtered_response, filter_metadata = result_filter.filter_result(
                llm_response, user_type, user_id
            )
            
            # Log filtering activity if significant
            if filter_metadata.get('filters_applied'):
                security_validator.log_security_event(
                    'RESULT_FILTERED',
                    {
                        'request_id': request_id,
                        'user_id': user_id,
                        'user_type': user_type,
                        'filter_metadata': filter_metadata
                    },
                    'INFO'
                )
            
            logger.info(f"Result filtering completed: {len(filter_metadata.get('filters_applied', []))} filters applied")
            
        except Exception as e:
            logger.warning(f"Result filtering failed: {e}")
            # Fallback to basic sanitization
            filtered_response = llm_response
        
        # Sanitize output for security (existing sanitization)
        sanitized_response = security_validator.sanitize_output(filtered_response)
        sanitized_context = security_validator.sanitize_output(context)
        
        # Log successful request
        security_validator.log_security_event(
            'SUCCESSFUL_REQUEST',
            {
                'request_id': request_id,
                'source_ip': source_ip,
                'user_type': user_type,
                'query_length': len(query_text),
                'response_length': len(sanitized_response)
            },
            'INFO'
        )

        # Return successful response with security headers
        return {
            'statusCode': 200,
            'headers': SecurityHeaders.get_security_headers(),
            'body': json.dumps({
                'question': query_text,
                'answer': sanitized_response,
                'source_context': sanitized_context,
                'request_id': request_id
            })
        }

    except ValueError as ve:
        # Handle invalid user type
        logger.error("ValueError occurred: %s", str(ve))
        return {
            'statusCode': 400,
            'headers': SecurityHeaders.get_security_headers(),
            'body': json.dumps({
                'error': str(ve),
                'message': 'Invalid user type provided.',
                'request_id': request_id if 'request_id' in locals() else 'unknown'
            })
        }
    except Exception as e:
        # Handle unexpected errors
        logger.error("Unexpected error occurred: %s", str(e))
        logger.error("Error type: %s", type(e))
        logger.error("Stacktrace: %s", traceback.format_exc())
        
        # Log security event for unexpected errors
        if 'security_validator' in locals():
            security_validator.log_security_event(
                'UNEXPECTED_ERROR',
                {
                    'request_id': request_id if 'request_id' in locals() else 'unknown',
                    'error_type': str(type(e)),
                    'error_message': str(e)
                },
                'HIGH'
            )
        
        return {
            'statusCode': 500,
            'headers': SecurityHeaders.get_security_headers(),
            'body': json.dumps({
                'error': 'Internal server error',
                'message': 'Error processing the request.',
                'request_id': request_id if 'request_id' in locals() else 'unknown'
            })
        }
